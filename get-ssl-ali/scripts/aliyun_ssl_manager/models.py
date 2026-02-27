"""Data models for SSL certificate management."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ServerConfig:
    """Single server deployment target."""

    host: str
    port: int
    user: str
    password: str
    cert_path: str
    key_path: str
    reload_cmd: str = "nginx -t && systemctl reload nginx"


@dataclass
class DomainConfig:
    """Domain with its deployment servers."""

    domain: str
    servers: list[ServerConfig] = field(default_factory=list)


@dataclass
class AliyunCredential:
    """Alibaba Cloud API credentials."""

    access_key_id: str
    access_key_secret: str


@dataclass
class Options:
    """Global options for the manager."""

    poll_interval: int = 10
    poll_timeout: int = 300
    renew_before_days: int = 14
    backup_old_cert: bool = True
    max_cert_validity_days: int = 199


@dataclass
class AcmeConfig:
    """ACME certificate provider configuration (Let's Encrypt / ZeroSSL)."""

    enabled: bool = False
    directory_url: str = "https://acme-v02.api.letsencrypt.org/directory"
    email: str = ""
    account_key_path: str = "./certs/acme_account.key"


@dataclass
class AppConfig:
    """Top-level application config."""

    aliyun: AliyunCredential
    cert_storage_dir: str
    domains: list[DomainConfig]
    options: Options
    acme: AcmeConfig = field(default_factory=AcmeConfig)

    def get_domain(self, domain_name: str) -> DomainConfig | None:
        """Find a domain config by name."""
        for d in self.domains:
            if d.domain == domain_name:
                return d
        return None

    def list_domains(self) -> list[str]:
        """Return all configured domain names."""
        return [d.domain for d in self.domains]
