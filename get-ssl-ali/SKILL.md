---
name: get-ssl-ali
description: >-
  SSL certificate automation: issue free certificates via ACME (Let's Encrypt) with Alibaba Cloud DNS-01 verification,
  deploy to servers via SSH/SFTP, and batch-renew expiring certs.
  Use this skill whenever the user mentions SSL certificates, HTTPS, cert renewal, Let's Encrypt, ACME,
  domain certificate management, nginx SSL setup, certificate expiry checking, or deploying certs to servers —
  even if they don't explicitly say "get-ssl-ali".
allowed-tools:
  - Bash(*)
  - Read(**)
argument-hint: <check|apply|deploy|renew|list|diagnose> [--domain <domain>] [--dry-run]
---

# SSL Certificate Automation

Manage SSL certificates via ACME (Let's Encrypt) + Alibaba Cloud DNS API.

## Commands

| Command | Action | Details |
|---------|--------|---------|
| `check` | Status check | ACME connectivity, certificate expiry, domain config |
| `apply` | Issue cert | ACME order → DNS-01 challenge → poll → download |
| `deploy` | Deploy cert | SSH/SFTP to servers: backup → upload → nginx test → reload |
| `renew` | Batch renew | Auto-renew certs expiring within threshold (default 14 days) |
| `list` | List config | Show configured domains and servers |
| `diagnose` | Diagnostics | Troubleshoot ACME, Alibaba Cloud API, config issues |

## How to Run

All paths below are relative to this skill's base directory (provided by Claude Code when the skill loads).

```
PYTHONPATH={skill_dir}/scripts python -m aliyun_ssl_manager <subcommand> [args]
```

- Python source: `scripts/aliyun_ssl_manager/`
- Config file: `config/config.yaml`
- Certificates: `certs/`

## Argument Parsing

User input: `$ARGUMENTS`

Parse the subcommand from `$ARGUMENTS` and execute accordingly:

| User Input | Command |
|------------|---------|
| `check` | `python -m aliyun_ssl_manager check` |
| `check --domain example.com` | `python -m aliyun_ssl_manager check --domain example.com` |
| `list` | `python -m aliyun_ssl_manager list` |
| `diagnose` | `python -m aliyun_ssl_manager diagnose` |
| `apply --domain example.com` | First `--dry-run`, then execute after confirmation |
| `deploy --domain example.com` | First `--dry-run`, then execute after confirmation |
| `renew` | First `--dry-run`, then execute after confirmation |
| `renew --domain example.com` | First `--dry-run`, then execute after confirmation |

## Safety Rules

For `apply`, `deploy`, and `renew` — always follow two-step execution:

1. **Dry run first**: run with `--dry-run` and show the execution plan to the user
2. **Wait for confirmation**: only proceed after the user explicitly confirms ("yes", "confirm", "go ahead")

Never execute `apply` / `deploy` / `renew` without user confirmation. This protects against accidental certificate operations that could affect production servers.

## Execution Flow

1. Parse `$ARGUMENTS` to determine subcommand and flags
2. For read-only commands (`check`, `list`, `diagnose`): execute directly and show results
3. For mutating commands (`apply`, `deploy`, `renew`):
   - Run with `--dry-run` first
   - Present the plan and ask for confirmation
   - Execute the real operation only after explicit user approval
4. Display the complete results

## Error Handling

- Missing environment variables → tell user which vars to set
- Config file not found → check `config/config.yaml` in this skill directory
- API errors → show full error message with troubleshooting suggestions
- ACME not enabled → set `acme.enabled: true` in config
- ACME connection failure → check network or `directory_url` config
- ACME timeout → DNS propagation may be slow, suggest retrying later
