# Aliyun SSL Manager

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)

[中文](README.md)

SSL certificate automation tool using ACME (Let's Encrypt) with Alibaba Cloud DNS-01 validation. Apply, deploy, and renew SSL certificates via CLI or [Claude Code](https://docs.anthropic.com/en/docs/claude-code) Skill.

## Features

- **check** - Check ACME status and certificate expiry
- **apply** - Apply for new certificate via ACME (Let's Encrypt) with automatic DNS-01 validation
- **deploy** - Deploy certificates to servers via SSH/SFTP (paramiko)
- **renew** - Batch renewal: check → apply → deploy
- **list** - List configured domains and servers
- **diagnose** - Diagnose ACME connectivity and API status

## Quick Start

### 1. Install Dependencies

```bash
pip install -e ./get-ssl-ali
```

> Requires Python 3.9+

### 2. Configure

```bash
cp get-ssl-ali/config/config.example.yaml get-ssl-ali/config/config.yaml
```

Edit `config.yaml`, key configuration fields:

```yaml
# Alibaba Cloud API credentials (recommend using environment variables)
aliyun:
  access_key_id: "${ALIYUN_ACCESS_KEY_ID}"
  access_key_secret: "${ALIYUN_ACCESS_KEY_SECRET}"

# ACME configuration (Let's Encrypt)
acme:
  enabled: true
  email: "${ACME_EMAIL}"                # Email for Let's Encrypt account registration

# Domain and server configuration (multiple domains supported, each can deploy to multiple servers)
domains:
  - domain: "example.com"               # Domain to issue certificate for
    servers:
      - host: "192.168.1.10"            # Server IP
        port: 22                        # SSH port
        user: "root"                    # SSH username
        password: "${SSH_PASS_SERVER1}" # SSH password (recommend using environment variables)
        cert_path: "/etc/nginx/ssl/example.com/fullchain.pem"  # Certificate deploy path
        key_path: "/etc/nginx/ssl/example.com/privkey.pem"     # Private key deploy path
        reload_cmd: "nginx -t && systemctl reload nginx"       # Command to run after deployment

# Optional settings
options:
  renew_before_days: 14   # Days before expiry to trigger renewal
  backup_old_cert: true   # Backup old certs before deploying
```

> Supports `${ENV_VAR}` syntax for environment variable substitution. Never put sensitive values directly in the config file.

### 3. Set Environment Variables

```bash
export ALIYUN_ACCESS_KEY_ID=your_key_id
export ALIYUN_ACCESS_KEY_SECRET=your_key_secret
export ACME_EMAIL=your_email@example.com
export SSH_PASS_SERVER1=your_ssh_password
```

### 4. Run

```bash
# Set PYTHONPATH
export PYTHONPATH=get-ssl-ali/scripts

# List configured domains
python -m aliyun_ssl_manager list

# Check ACME status and cert expiry
python -m aliyun_ssl_manager check

# Apply for a certificate (dry-run first)
python -m aliyun_ssl_manager apply --domain example.com --dry-run
python -m aliyun_ssl_manager apply --domain example.com

# Deploy to servers
python -m aliyun_ssl_manager deploy --domain example.com --dry-run
python -m aliyun_ssl_manager deploy --domain example.com

# Batch renew all due certificates
python -m aliyun_ssl_manager renew --dry-run
python -m aliyun_ssl_manager renew
```

## Install as Claude Code Skill

Copy or symlink `get-ssl-ali/` to your project's `.claude/skills/` directory:

```bash
# Option 1: Symlink (Linux/macOS — recommended for development)
ln -s /path/to/get-ssl-ali .claude/skills/get-ssl-ali

# Option 2: Symlink (Windows — use PowerShell, no admin required)
# Note: ln -s on Windows creates a plain directory copy, NOT a real symlink.
# Use a Junction (directory link) instead:
New-Item -ItemType Junction -Path ".claude\skills\get-ssl-ali" -Target "\path\to\get-ssl-ali\get-ssl-ali"

# Option 3: Copy
cp -r /path/to/get-ssl-ali .claude/skills/get-ssl-ali
```

Then use in Claude Code:

```
/get-ssl-ali check
/get-ssl-ali list
/get-ssl-ali apply --domain example.com
/get-ssl-ali deploy --domain example.com
/get-ssl-ali renew
```

Apply/deploy/renew will always show a dry-run plan first and require confirmation.

## Certificate Apply Flow (ACME 6 Steps)

1. **Register/load ACME account** → Account key management
2. **Create ACME order** → Get dns-01 challenge for domain
3. **Add DNS TXT record** (Aliyun DNS API) → Auto-add validation record
4. **Answer ACME challenge** → Notify Let's Encrypt to verify
5. **Poll ACME order** → Wait for validation + finalize (up to 5 min)
6. **Save cert + cleanup DNS** → Store fullchain.pem + privkey.pem locally

## Deploy Flow

1. SSH connect (paramiko)
2. Backup old certificates
3. SFTP upload new cert and key
4. Set permissions (cert: 644, key: 600)
5. `nginx -t` validation
6. Reload nginx (auto-rollback on failure)

## Project Structure

```
get-ssl-ali/
├── get-ssl-ali/                    # Skill package (can be installed to .claude/skills/)
│   ├── SKILL.md                    # Claude Code skill definition
│   ├── pyproject.toml
│   ├── config/
│   │   ├── config.example.yaml
│   │   └── config.yaml             # (gitignored)
│   ├── certs/                      # (gitignored)
│   └── scripts/aliyun_ssl_manager/
│       ├── __main__.py             # python -m entry
│       ├── cli.py                  # argparse subcommands
│       ├── config.py               # YAML loading + env var substitution
│       ├── models.py               # dataclass models
│       ├── api/
│       │   ├── acme_client.py      # ACME v2 protocol (Let's Encrypt)
│       │   ├── cas_client.py       # Aliyun CAS API (read-only, legacy)
│       │   └── dns_client.py       # Aliyun DNS API
│       ├── core/
│       │   ├── cert_manager.py     # ACME 6-step flow orchestration
│       │   ├── deployer.py         # SSH deployment (paramiko)
│       │   └── validator.py        # DNS validation management
│       └── utils/
│           ├── logger.py           # Structured logging
│           └── retry.py            # Polling utility
├── LICENSE
├── README.md
└── README_EN.md
```

## Contributing

Contributions are welcome! Feel free to open an issue or submit a pull request.

1. Fork this repository
2. Create your feature branch (`git checkout -b feature/awesome-feature`)
3. Commit your changes (`git commit -m 'feat: add awesome feature'`)
4. Push to the branch (`git push origin feature/awesome-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
