"""Certificate lifecycle manager - orchestrates the 6-step ACME flow.

All certificate issuance goes through ACME (Let's Encrypt) with DNS-01
validation via Aliyun DNS API. CAS API is only used read-only for
querying legacy certificate records.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from aliyun_ssl_manager.api.cas_client import CasClient
from aliyun_ssl_manager.api.dns_client import DnsClient
from aliyun_ssl_manager.models import AppConfig
from aliyun_ssl_manager.utils.logger import log


def _parse_cert_time(raw_time) -> datetime | None:
    """Parse certificate timestamp, handling both string dates and epoch millis.

    Args:
        raw_time: String date, epoch millis (int/str), or None.

    Returns:
        datetime object (UTC) or None if unparseable.
    """
    if raw_time is None:
        return None

    if isinstance(raw_time, (int, float)):
        try:
            return datetime.fromtimestamp(raw_time / 1000, tz=timezone.utc)
        except (ValueError, OSError, OverflowError):
            return None

    if isinstance(raw_time, str):
        try:
            ts = int(raw_time)
            if ts > 1_000_000_000_000:
                return datetime.fromtimestamp(ts / 1000, tz=timezone.utc)
        except ValueError:
            pass

        for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S", "%Y/%m/%d"):
            try:
                return datetime.strptime(raw_time, fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                continue

    return None


def _format_cert_time(raw_time) -> str:
    """Format raw cert time to human-readable string."""
    dt = _parse_cert_time(raw_time)
    if dt is None:
        return str(raw_time) if raw_time is not None else "N/A"
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


class CertManager:
    """Orchestrates certificate check / apply / deploy / renew / diagnose.

    Uses ACME (Let's Encrypt) exclusively for certificate issuance.
    DNS-01 validation via Aliyun DNS API.
    """

    def __init__(self, config: AppConfig):
        self._config = config
        self._cas = CasClient(credential=config.aliyun)
        self._dns = DnsClient(config.aliyun)

    # ── check ────────────────────────────────────────────────────

    def check(self, domain: str | None = None) -> None:
        """Check ACME status and existing certificate expiry."""
        print("=" * 60)
        print("  SSL Certificate Status Check")
        print("=" * 60)

        # ACME status
        print("\n  [ACME Mode]")
        if self._config.acme.enabled:
            print(f"    Status: ENABLED")
            print(f"    Directory: {self._config.acme.directory_url}")
            print(f"    Email: {self._config.acme.email}")
            print(f"    Account key: {self._config.acme.account_key_path}")
            from aliyun_ssl_manager.api.acme_client import AcmeClient
            acme = AcmeClient(self._config.acme)
            result = acme.check_connectivity()
            if result["ok"]:
                print(f"    Connectivity: OK")
            else:
                print(f"    Connectivity: FAILED - {result.get('error', 'unknown')}")
        else:
            print(f"    Status: DISABLED")
            print(f"    Set acme.enabled=true in config.yaml to enable")

        # Check existing certificates
        domains_to_check = (
            [domain] if domain else self._config.list_domains()
        )

        print(f"\n  Checking {len(domains_to_check)} domain(s)...")
        print("-" * 60)

        for d in domains_to_check:
            self._check_domain_certs(d)

        print("=" * 60)

    def _check_local_cert(self, domain: str) -> bool:
        """Check local certificate file and print its details.

        Returns:
            True if local cert was found and displayed, False otherwise.
        """
        cert_file = Path(self._config.cert_storage_dir) / domain / "fullchain.pem"
        if not cert_file.exists():
            return False

        try:
            from cryptography import x509 as cx509

            cert_data = cert_file.read_bytes()
            cert = cx509.load_pem_x509_certificate(cert_data)

            issuer = cert.issuer
            try:
                from cryptography.x509.oid import NameOID
                issuer_cn = issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
                issuer_o = issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
                issuer_name = (
                    issuer_cn[0].value if issuer_cn
                    else issuer_o[0].value if issuer_o
                    else str(issuer)
                )
            except Exception:
                issuer_name = str(issuer)

            not_before = cert.not_valid_before_utc
            not_after = cert.not_valid_after_utc
            now_utc = datetime.now(tz=timezone.utc)
            delta = not_after - now_utc
            days_left = delta.days

            needs_renew = days_left <= self._config.options.renew_before_days
            renew_flag = " *** NEEDS RENEWAL ***" if needs_renew else ""

            print(f"\n  {domain}:")
            print(f"    Source:  Local ({cert_file})")
            print(f"    Issuer:  {issuer_name}")
            print(f"    From:    {not_before.strftime('%Y-%m-%d %H:%M:%S UTC')}")
            print(f"    Expires: {not_after.strftime('%Y-%m-%d %H:%M:%S UTC')} ({days_left} days){renew_flag}")
            return True

        except Exception as e:
            print(f"\n  {domain}: Local cert parse error - {e}")
            return False

    def _check_domain_certs(self, domain: str) -> None:
        """Check certificate status for a single domain.

        Priority: local fullchain.pem first, then fallback to Aliyun CAS records.
        """
        if self._check_local_cert(domain):
            return

        # Fallback: query Aliyun CAS records (legacy certificates)
        try:
            orders = self._cas.list_user_certificates(keyword=domain)
            if not orders:
                print(f"\n  {domain}: No certificates found (local or CAS)")
                return

            for order in orders:
                if order.get("domain") and domain not in order["domain"]:
                    continue
                status = order.get("status", "unknown")
                end_time_raw = order.get("cert_end_time")

                days_left = "N/A"
                needs_renew = False
                end_dt = _parse_cert_time(end_time_raw)
                if end_dt:
                    now_utc = datetime.now(tz=timezone.utc)
                    delta = end_dt - now_utc
                    days_left = f"{delta.days} days"
                    needs_renew = delta.days <= self._config.options.renew_before_days

                renew_flag = " *** NEEDS RENEWAL ***" if needs_renew else ""
                display_time = _format_cert_time(end_time_raw)
                print(f"\n  {order.get('domain', domain)}:")
                print(f"    Source:  Aliyun CAS (legacy)")
                print(f"    Status:  {status}")
                print(f"    Expires: {display_time} ({days_left}){renew_flag}")
                print(f"    OrderID: {order.get('order_id', 'N/A')}")

        except Exception as e:
            print(f"\n  {domain}: Error checking - {e}")

    # ── apply ────────────────────────────────────────────────────

    def apply(self, domain: str, dry_run: bool = False) -> None:
        """Apply for a new certificate via ACME (Let's Encrypt)."""
        dc = self._config.get_domain(domain)
        if not dc:
            log.error(f"Domain '{domain}' not found in config")
            return

        if not self._config.acme.enabled:
            log.error(
                "ACME is not enabled! Set acme.enabled=true in config.yaml"
            )
            return

        if dry_run:
            self._show_apply_plan(dc)
            return

        self._execute_apply(domain)

    def _show_apply_plan(self, dc) -> None:
        """Show what apply would do without executing."""
        print("=" * 60)
        print("  Certificate Apply Plan (DRY RUN)")
        print("=" * 60)
        print(f"\n  Domain: {dc.domain}")
        print(f"  Mode: ACME (Let's Encrypt via {self._config.acme.directory_url})")
        print(f"\n  Steps:")
        print(f"    [1/6] Register/load ACME account")
        print(f"    [2/6] Create ACME order + get dns-01 challenge")
        print(f"    [3/6] Add TXT DNS validation record (Aliyun DNS)")
        print(f"    [4/6] Answer ACME challenge")
        print(f"    [5/6] Poll ACME order until valid (up to {self._config.options.poll_timeout}s)")
        print(f"    [6/6] Finalize + download cert + cleanup DNS")
        print(f"\n  Storage: {self._config.cert_storage_dir}/{dc.domain}/")
        print("=" * 60)

    def _execute_apply(self, domain: str) -> dict | None:
        """Execute the 6-step ACME certificate application flow.

        Returns:
            dict with cert/key paths if successful, None on failure.
        """
        from aliyun_ssl_manager.api.acme_client import AcmeClient
        from aliyun_ssl_manager.core.validator import DnsValidator

        acme = AcmeClient(self._config.acme)
        log.set_total_steps(6)

        # [1/6] Register ACME account
        log.step("Registering/loading ACME account")
        try:
            acme.register_or_load()
            log.success(f"ACME account ready ({self._config.acme.directory_url})")
        except Exception as e:
            log.error(f"ACME account registration failed: {e!r}")
            return None

        # [2/6] Create order + get dns-01 challenge
        log.step("Creating ACME order and getting dns-01 challenge")
        try:
            order, challenge_info = acme.request_certificate(domain)
            record_name = challenge_info["record_name"]
            validation = challenge_info["validation"]
            log.success(
                f"dns-01 challenge: {record_name} TXT = {validation[:32]}..."
            )
        except Exception as e:
            log.error(f"ACME order failed: {e!r}")
            return None

        # [3/6] Add DNS TXT record via Aliyun DNS
        log.step("Adding DNS validation record via Aliyun DNS")
        validator = DnsValidator(self._dns)
        try:
            root_domain, rr = validator.parse_record_domain(record_name, domain)
            record_id = validator.add_validation_record(
                root_domain=root_domain,
                rr=rr,
                record_type="TXT",
                value=validation,
            )
            log.success(f"DNS record added (id={record_id})")
        except Exception as e:
            log.error(f"Failed to add DNS record: {e}")
            return None

        # [4/6] Answer ACME challenge
        log.step("Answering ACME challenge")
        try:
            acme.answer_challenge(challenge_info["challenge_body"])
            log.success("Challenge answered, ACME server will verify DNS")
        except Exception as e:
            log.error(f"Failed to answer challenge: {e}")
            return None

        # [5/6] Poll ACME order + finalize + download cert
        log.step(
            f"Polling ACME order and finalizing (timeout={self._config.options.poll_timeout}s)"
        )
        try:
            fullchain_pem, private_key_pem = acme.poll_and_finalize(
                order, timeout=self._config.options.poll_timeout
            )
            log.success("Certificate issued by Let's Encrypt!")
        except TimeoutError:
            log.error(
                f"Timed out after {self._config.options.poll_timeout}s. "
                "DNS propagation may be slow. Try again later."
            )
            return None
        except RuntimeError as e:
            log.error(str(e))
            return None
        except Exception as e:
            log.error(f"ACME finalization failed: {e!r}")
            return None

        # [6/6] Save certificate + cleanup DNS
        log.step("Saving certificate and cleaning up DNS")
        try:
            cert_dir = Path(self._config.cert_storage_dir) / domain
            cert_dir.mkdir(parents=True, exist_ok=True)

            cert_path = cert_dir / "fullchain.pem"
            key_path = cert_dir / "privkey.pem"

            cert_path.write_text(fullchain_pem, encoding="utf-8")
            key_path.write_text(private_key_pem, encoding="utf-8")
            log.success(f"Certificate saved to {cert_dir}")

            try:
                validator.cleanup(root_domain, rr, "TXT")
            except Exception as e:
                log.warn(f"DNS cleanup failed (non-critical): {e}")

            return {
                "cert_path": str(cert_path),
                "key_path": str(key_path),
                "domain": domain,
            }

        except Exception as e:
            log.error(f"Failed to save certificate: {e}")
            return None

    # ── deploy ───────────────────────────────────────────────────

    def deploy(
        self, domain: str, server: str | None = None, dry_run: bool = False
    ) -> None:
        """Deploy certificate to server(s)."""
        dc = self._config.get_domain(domain)
        if not dc:
            log.error(f"Domain '{domain}' not found in config")
            return

        cert_dir = Path(self._config.cert_storage_dir) / domain
        cert_path = cert_dir / "fullchain.pem"
        key_path = cert_dir / "privkey.pem"

        if not cert_path.exists() or not key_path.exists():
            log.error(
                f"Local certificate files not found in {cert_dir}. "
                f"Run 'apply --domain {domain}' first."
            )
            return

        servers = dc.servers
        if server:
            servers = [s for s in servers if s.host == server]
            if not servers:
                log.error(f"Server '{server}' not found for domain {domain}")
                return

        if dry_run:
            self._show_deploy_plan(domain, servers, cert_path, key_path)
            return

        self._execute_deploy(domain, servers, cert_path, key_path)

    def _show_deploy_plan(self, domain, servers, cert_path, key_path) -> None:
        """Show deploy plan without executing."""
        print("=" * 60)
        print("  Certificate Deploy Plan (DRY RUN)")
        print("=" * 60)
        print(f"\n  Domain: {domain}")
        print(f"  Local cert: {cert_path}")
        print(f"  Local key:  {key_path}")
        print(f"  Backup old: {self._config.options.backup_old_cert}")
        print(f"\n  Target servers ({len(servers)}):")
        for s in servers:
            print(f"    - {s.user}@{s.host}:{s.port}")
            print(f"      cert -> {s.cert_path}")
            print(f"      key  -> {s.key_path}")
            print(f"      then: {s.reload_cmd}")
        print("=" * 60)

    def _execute_deploy(self, domain, servers, cert_path, key_path) -> None:
        """Execute deployment to all target servers."""
        from aliyun_ssl_manager.core.deployer import Deployer

        deployer = Deployer(backup=self._config.options.backup_old_cert)
        success_count = 0

        for s in servers:
            log.info(f"Deploying to {s.user}@{s.host}:{s.port}")
            try:
                deployer.deploy(
                    server=s,
                    local_cert=str(cert_path),
                    local_key=str(key_path),
                )
                success_count += 1
                log.success(f"Deploy to {s.host} completed")
            except Exception as e:
                log.error(f"Deploy to {s.host} failed: {e}")

        total = len(servers)
        if success_count == total:
            log.success(f"All {total} server(s) deployed successfully for {domain}")
        else:
            log.warn(f"{success_count}/{total} server(s) deployed for {domain}")

    # ── renew ────────────────────────────────────────────────────

    def renew(self, domain: str | None = None, dry_run: bool = False) -> None:
        """Batch renew: check expiry -> apply -> deploy for due domains."""
        domains_to_check = (
            [domain] if domain else self._config.list_domains()
        )

        domains_to_renew = []
        for d in domains_to_check:
            if self._needs_renewal(d):
                domains_to_renew.append(d)

        if not domains_to_renew:
            print("No domains need renewal at this time.")
            return

        print(f"\n  Domains needing renewal: {len(domains_to_renew)}")
        for d in domains_to_renew:
            print(f"    - {d}")
        print()

        if dry_run:
            for d in domains_to_renew:
                dc = self._config.get_domain(d)
                if dc:
                    self._show_apply_plan(dc)
                    self._show_deploy_plan(
                        d, dc.servers,
                        Path(self._config.cert_storage_dir) / d / "fullchain.pem",
                        Path(self._config.cert_storage_dir) / d / "privkey.pem",
                    )
            return

        for d in domains_to_renew:
            print(f"\n{'='*60}")
            print(f"  Renewing: {d}")
            print(f"{'='*60}")

            result = self._execute_apply(d)
            if result:
                dc = self._config.get_domain(d)
                if dc and dc.servers:
                    self._execute_deploy(
                        d, dc.servers,
                        Path(result["cert_path"]),
                        Path(result["key_path"]),
                    )

    def _needs_renewal(self, domain: str) -> bool:
        """Check if a domain's certificate needs renewal.

        Checks local certificate files first, then falls back to CAS records.
        """
        cert_file = Path(self._config.cert_storage_dir) / domain / "fullchain.pem"
        if cert_file.exists():
            try:
                from cryptography import x509 as cx509

                cert_data = cert_file.read_bytes()
                cert = cx509.load_pem_x509_certificate(cert_data)
                now_utc = datetime.now(tz=timezone.utc)
                delta = cert.not_valid_after_utc - now_utc
                if delta.days > self._config.options.renew_before_days:
                    return False
            except Exception:
                pass

        # Fallback: check legacy CAS records
        try:
            orders = self._cas.list_user_certificates(keyword=domain)
            if not orders:
                return True

            for order in orders:
                if order.get("domain") and domain not in order.get("domain", ""):
                    continue
                end_time_raw = order.get("cert_end_time")
                if not end_time_raw:
                    continue

                end_dt = _parse_cert_time(end_time_raw)
                if not end_dt:
                    continue

                now_utc = datetime.now(tz=timezone.utc)
                delta = end_dt - now_utc
                if delta.days > self._config.options.renew_before_days:
                    return False

            return True
        except Exception:
            return True

    # ── diagnose ─────────────────────────────────────────────────

    def diagnose(self) -> None:
        """Diagnose ACME connectivity and Aliyun API status."""
        print("=" * 60)
        print("  SSL Certificate Diagnostic Report")
        print("=" * 60)

        # Phase 1: ACME status
        print("\n  [1/3] ACME (Let's Encrypt) status...")
        if self._config.acme.enabled:
            print(f"    ENABLED")
            print(f"    Directory: {self._config.acme.directory_url}")
            print(f"    Email: {self._config.acme.email}")
            print(f"    Account key: {self._config.acme.account_key_path}")
            from aliyun_ssl_manager.api.acme_client import AcmeClient
            acme = AcmeClient(self._config.acme)
            conn = acme.check_connectivity()
            if conn["ok"]:
                print(f"    Connectivity: OK (endpoints: {', '.join(conn['endpoints'][:4])})")
                key_path = Path(self._config.acme.account_key_path)
                print(f"    Account key exists: {'YES' if key_path.exists() else 'NO (will be created on first use)'}")
            else:
                print(f"    Connectivity: FAILED - {conn.get('error', 'unknown')}")
        else:
            print(f"    DISABLED (set acme.enabled=true in config.yaml to enable)")

        # Phase 2: Aliyun API connectivity (read-only)
        print("\n  [2/3] Testing Aliyun API connectivity...")
        try:
            certs = self._cas.list_user_certificates()
            print(f"    CAS API: OK - found {len(certs)} certificate record(s)")
            if certs:
                for c in certs[:3]:
                    end_display = _format_cert_time(c.get("cert_end_time"))
                    print(f"    - {c.get('domain', '?')}: status={c.get('status', '?')}, expires={end_display}")
                if len(certs) > 3:
                    print(f"    ... and {len(certs) - 3} more")
        except Exception as e:
            print(f"    CAS API: FAILED - {e}")

        # Phase 3: Recommendations
        print("\n  [3/3] Recommendations:")
        if self._config.acme.enabled:
            print(f"\n    ACME mode is ACTIVE")
            print(f"    Certificates will be issued by Let's Encrypt.")
            print(f"    DNS validation via Aliyun DNS API.")
        else:
            print(f"\n    ACME is DISABLED!")
            print(f"    Enable it in config.yaml:")
            print(f"    acme:")
            print(f"      enabled: true")
            print(f"      email: 'you@example.com'")

        print("=" * 60)
