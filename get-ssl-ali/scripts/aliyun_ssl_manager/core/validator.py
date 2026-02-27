"""DNS validation record management."""

from __future__ import annotations

from aliyun_ssl_manager.api.dns_client import DnsClient
from aliyun_ssl_manager.utils.logger import log


class DnsValidator:
    """Manages DNS validation records for certificate issuance."""

    def __init__(self, dns_client: DnsClient):
        self._dns = dns_client

    @staticmethod
    def parse_record_domain(record_domain: str, target_domain: str) -> tuple[str, str]:
        """Parse the full record domain into root domain and RR (host record).

        The ACME DNS-01 challenge requires a TXT record like
        "_acme-challenge.example.com" or "_acme-challenge.sub.example.com".
        We need to split it into:
        - root_domain: the registered domain (e.g. "example.com")
        - rr: the host record (e.g. "_acme-challenge" or "_acme-challenge.sub")

        Args:
            record_domain: Full validation domain for DNS-01 challenge.
            target_domain: The domain being validated.

        Returns:
            Tuple of (root_domain, rr).
        """
        # Extract root domain from target: if target is "sub.example.com",
        # root is "example.com" (last two parts)
        parts = target_domain.split(".")
        if len(parts) >= 2:
            root_domain = ".".join(parts[-2:])
        else:
            root_domain = target_domain

        # The RR is everything before the root domain in record_domain
        if record_domain.endswith("." + root_domain):
            rr = record_domain[: -(len(root_domain) + 1)]
        elif record_domain.endswith(root_domain):
            rr = record_domain[: -len(root_domain)].rstrip(".")
        else:
            # Fallback: use the full record_domain as rr
            rr = record_domain
            log.warn(
                f"Could not parse root domain from '{record_domain}', "
                f"using full value as RR"
            )

        return root_domain, rr

    def add_validation_record(
        self,
        root_domain: str,
        rr: str,
        record_type: str,
        value: str,
    ) -> str:
        """Add a DNS validation record, cleaning up any existing duplicates first.

        Args:
            root_domain: The root domain (e.g. "example.com").
            rr: Host record (e.g. "_dnsauth").
            record_type: Record type (usually "TXT").
            value: Validation value.

        Returns:
            The new record ID.
        """
        # Clean up old validation records with same RR
        try:
            self._dns.cleanup_validation_records(root_domain, rr, record_type)
        except Exception as e:
            log.warn(f"Cleanup of old records failed (non-critical): {e}")

        # Add new validation record
        return self._dns.add_record(
            domain=root_domain,
            rr=rr,
            record_type=record_type,
            value=value,
        )

    def cleanup(self, root_domain: str, rr: str, record_type: str = "TXT") -> None:
        """Clean up validation DNS records.

        Args:
            root_domain: The root domain.
            rr: Host record to clean.
            record_type: Record type to clean.
        """
        self._dns.cleanup_validation_records(root_domain, rr, record_type)
