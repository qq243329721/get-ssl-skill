"""ACME protocol client for Let's Encrypt / ZeroSSL certificate issuance.

Uses the ``acme`` library (certbot's underlying lib) + ``josepy`` for JOSE.
Pure Python implementation, no external CLI dependency.

Flow:
    1. register_or_load()          → setup ACME account
    2. request_certificate(domain) → create order + extract dns-01 info
    3. answer_challenge()          → notify server DNS is ready
    4. poll_and_finalize()         → wait + finalize + download cert
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import josepy as jose
from acme import challenges, client, errors as acme_errors, messages
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from aliyun_ssl_manager.models import AcmeConfig
from aliyun_ssl_manager.utils.logger import log

_USER_AGENT = "aliyun-ssl-manager/0.1.0"


class AcmeClient:
    """ACME v2 certificate client.

    Wraps the full dns-01 issuance flow against Let's Encrypt or any
    RFC 8555-compliant server.
    """

    def __init__(self, config: AcmeConfig):
        self._config = config
        self._account_key: jose.JWK | None = None
        self._acme_client: client.ClientV2 | None = None
        # Cert private key generated during request_certificate, returned in finalize
        self._cert_private_key = None

    # ── Account Management ────────────────────────────────────────

    def register_or_load(self) -> None:
        """Register a new ACME account or load an existing one.

        The account key (EC P-256) is persisted to ``account_key_path``
        so we can reuse the same registration across runs.
        """
        key_path = Path(self._config.account_key_path)
        key_path.parent.mkdir(parents=True, exist_ok=True)

        if key_path.exists():
            log.info("Loading existing ACME account key")
            private_key = serialization.load_pem_private_key(
                key_path.read_bytes(), password=None
            )
        else:
            log.info("Generating new ACME account key (EC P-256)")
            private_key = ec.generate_private_key(ec.SECP256R1())
            key_path.write_bytes(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )

        self._account_key = jose.JWK.load(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

        # Build ACME client from directory URL
        # EC P-256 keys require ES256 algorithm (default is RS256 for RSA)
        net = client.ClientNetwork(
            self._account_key, user_agent=_USER_AGENT, alg=jose.ES256
        )
        directory = messages.Directory.from_json(
            net.get(self._config.directory_url).json()
        )
        self._acme_client = client.ClientV2(directory, net=net)

        # Register or find existing account
        reg = messages.NewRegistration.from_data(
            email=self._config.email,
            terms_of_service_agreed=True,
        )
        try:
            self._acme_client.new_account(reg)
            log.info("ACME account registered")
        except acme_errors.ConflictError as e:
            # Account exists - load it via the Location URL from the error
            log.info("ACME account already exists, reusing")
            existing_regr = messages.RegistrationResource(
                uri=e.location,
                body=messages.Registration(),
            )
            self._acme_client.net.account = existing_regr
            self._acme_client.query_registration(existing_regr)

    # ── Certificate Issuance ──────────────────────────────────────

    def request_certificate(self, domain: str) -> tuple[messages.OrderResource, dict]:
        """Create a new order and extract dns-01 challenge info.

        Generates a fresh RSA-2048 key + CSR for the certificate,
        creates the ACME order, and locates the dns-01 challenge.

        Args:
            domain: FQDN to request a certificate for.

        Returns:
            Tuple of (order, challenge_info).
            challenge_info keys:
                - domain: identifier domain value
                - record_name: ``_acme-challenge.{domain}``
                - validation: TXT record value to set
                - challenge_body: ChallengeBody (pass to answer_challenge)
        """
        self._ensure_client()

        # Generate cert private key (RSA-2048)
        self._cert_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        # Build CSR
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(
                x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)])
            )
            .sign(self._cert_private_key, hashes.SHA256())
        )
        csr_pem = csr.public_bytes(serialization.Encoding.PEM)

        # Create ACME order (the library stores the CSR in OrderResource)
        order = self._acme_client.new_order(csr_pem)
        log.info(f"ACME order created for {domain}")

        # Locate dns-01 challenge
        challenge_info = self._find_dns01_challenge(order)
        return order, challenge_info

    def answer_challenge(self, challenge_body: messages.ChallengeBody) -> None:
        """Notify the ACME server that the DNS record is in place.

        Args:
            challenge_body: From the ``challenge_info`` returned by
                ``request_certificate()``.
        """
        self._ensure_client()
        response = challenge_body.response(self._account_key)
        self._acme_client.answer_challenge(challenge_body, response)
        log.info("ACME challenge answered")

    def poll_and_finalize(
        self, order: messages.OrderResource, *, timeout: int = 300
    ) -> tuple[str, str]:
        """Wait for validation, finalize, and download the certificate.

        Uses the library's built-in ``poll_and_finalize`` which handles:
        1. Polling authorizations until all are valid
        2. Sending the CSR to finalize the order
        3. Downloading the issued certificate chain

        Args:
            order: OrderResource from ``request_certificate()``.
            timeout: Max seconds to wait for validation + issuance.

        Returns:
            Tuple of (fullchain_pem, private_key_pem).

        Raises:
            TimeoutError: If validation does not complete in time.
            RuntimeError: If the order becomes invalid.
        """
        self._ensure_client()
        if self._cert_private_key is None:
            raise RuntimeError("No cert key found. Call request_certificate() first.")

        # acme library uses naive local datetime internally (datetime.now()),
        # so we must pass a naive local deadline to match
        deadline = datetime.now() + timedelta(seconds=timeout)

        try:
            finalized = self._acme_client.poll_and_finalize(order, deadline=deadline)
        except acme_errors.TimeoutError:
            raise TimeoutError(
                f"ACME order did not complete within {timeout}s. "
                "DNS propagation may be slow - retry later."
            )
        except acme_errors.ValidationError as e:
            raise RuntimeError(
                f"ACME validation failed: {e!r}. Check DNS records."
            ) from e

        # Extract fullchain PEM
        fullchain_pem = finalized.fullchain_pem

        # Export cert private key as PEM
        private_key_pem = self._cert_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")

        # Clear the key reference (one-shot use)
        self._cert_private_key = None

        return fullchain_pem, private_key_pem

    # ── Diagnostics ───────────────────────────────────────────────

    def check_connectivity(self) -> dict:
        """Test connectivity to the ACME directory server.

        Returns:
            dict with ``ok``, ``url``, and either ``endpoints`` or ``error``.
        """
        try:
            import urllib.request

            url = self._config.directory_url
            req = urllib.request.Request(url, method="GET")
            req.add_header("User-Agent", _USER_AGENT)
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())
                return {"ok": True, "url": url, "endpoints": list(data.keys())}
        except Exception as e:
            return {"ok": False, "url": self._config.directory_url, "error": str(e)}

    # ── Internal ──────────────────────────────────────────────────

    def _find_dns01_challenge(
        self, order: messages.OrderResource
    ) -> dict:
        """Locate the dns-01 challenge in an order's authorizations."""
        for authz in order.authorizations:
            domain = authz.body.identifier.value
            for challb in authz.body.challenges:
                if isinstance(challb.chall, challenges.DNS01):
                    validation = challb.chall.validation(self._account_key)
                    return {
                        "domain": domain,
                        "record_name": f"_acme-challenge.{domain}",
                        "validation": validation,
                        "challenge_body": challb,
                    }

        raise RuntimeError(
            "No dns-01 challenge found in ACME order. "
            "Server may not support DNS validation for this request."
        )

    def _ensure_client(self) -> None:
        """Ensure the ACME client has been initialized."""
        if self._acme_client is None:
            raise RuntimeError(
                "ACME client not initialized. Call register_or_load() first."
            )
