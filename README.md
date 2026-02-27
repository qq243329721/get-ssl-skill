# 阿里云 SSL 证书管理工具

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)

[English](README_EN.md)

基于 ACME (Let's Encrypt) + 阿里云 DNS 的 SSL 证书自动化工具，支持证书申请、部署、批量续期，可作为 [Claude Code](https://docs.anthropic.com/en/docs/claude-code) 技能使用。

## 功能特性

- **check** - 检查 ACME 状态和证书过期时间
- **apply** - 通过 ACME (Let's Encrypt) 自动申请免费证书，DNS-01 自动验证
- **deploy** - 通过 SSH/SFTP 部署证书到服务器
- **renew** - 批量续期：检查 → 申请 → 部署
- **list** - 列出已配置的域名和服务器
- **diagnose** - 诊断 ACME 连接和 API 状态

## 快速开始

### 1. 安装依赖

```bash
pip install -e ./get-ssl-ali
```

> 需要 Python 3.9+

### 2. 配置

```bash
cp get-ssl-ali/config/config.example.yaml get-ssl-ali/config/config.yaml
```

编辑 `config.yaml`，主要配置项说明：

```yaml
# 阿里云 API 凭证（建议通过环境变量设置）
aliyun:
  access_key_id: "${ALIYUN_ACCESS_KEY_ID}"
  access_key_secret: "${ALIYUN_ACCESS_KEY_SECRET}"

# ACME 配置（Let's Encrypt）
acme:
  enabled: true
  email: "${ACME_EMAIL}"                # 用于注册 Let's Encrypt 账户

# 域名和服务器配置（可配置多个域名，每个域名可部署到多台服务器）
domains:
  - domain: "example.com"               # 要申请证书的域名
    servers:
      - host: "192.168.1.10"            # 服务器 IP
        port: 22                        # SSH 端口
        user: "root"                    # SSH 用户名
        password: "${SSH_PASS_SERVER1}" # SSH 密码（建议通过环境变量设置）
        cert_path: "/etc/nginx/ssl/example.com/fullchain.pem"  # 证书部署路径
        key_path: "/etc/nginx/ssl/example.com/privkey.pem"     # 私钥部署路径
        reload_cmd: "nginx -t && systemctl reload nginx"       # 部署后执行的命令

# 可选参数
options:
  renew_before_days: 14   # 提前多少天续期
  backup_old_cert: true   # 部署前备份旧证书
```

> 支持 `${ENV_VAR}` 语法引用环境变量，敏感信息不要直接写在配置文件中。

### 3. 设置环境变量

```bash
export ALIYUN_ACCESS_KEY_ID=你的AccessKeyID
export ALIYUN_ACCESS_KEY_SECRET=你的AccessKeySecret
export ACME_EMAIL=你的邮箱@example.com
export SSH_PASS_SERVER1=你的SSH密码
```

### 4. 运行

```bash
# 设置 PYTHONPATH
export PYTHONPATH=get-ssl-ali/scripts

# 列出已配置的域名
python -m aliyun_ssl_manager list

# 检查 ACME 状态和证书过期时间
python -m aliyun_ssl_manager check

# 申请证书（先 dry-run 预览）
python -m aliyun_ssl_manager apply --domain example.com --dry-run
python -m aliyun_ssl_manager apply --domain example.com

# 部署到服务器
python -m aliyun_ssl_manager deploy --domain example.com --dry-run
python -m aliyun_ssl_manager deploy --domain example.com

# 批量续期所有即将过期的证书
python -m aliyun_ssl_manager renew --dry-run
python -m aliyun_ssl_manager renew
```

## 作为 Claude Code 技能使用

将 `get-ssl-ali/` 复制或软链接到项目的 `.claude/skills/` 目录：

```bash
# 方式一：软链接（推荐，方便开发）
ln -s /path/to/get-ssl-ali .claude/skills/get-ssl-ali

# 方式二：复制
cp -r /path/to/get-ssl-ali .claude/skills/get-ssl-ali
```

然后在 Claude Code 中使用：

```
/get-ssl-ali check
/get-ssl-ali list
/get-ssl-ali apply --domain example.com
/get-ssl-ali deploy --domain example.com
/get-ssl-ali renew
```

apply/deploy/renew 会先执行 dry-run 预览操作计划，确认后才实际执行。

## 证书申请流程（ACME 6 步）

1. **注册/加载 ACME 账户** → 账户密钥管理
2. **创建 ACME 订单** → 获取域名的 dns-01 验证挑战
3. **添加 DNS TXT 记录**（阿里云 DNS API）→ 自动添加验证记录
4. **应答 ACME 挑战** → 通知 Let's Encrypt 进行验证
5. **轮询 ACME 订单** → 等待验证完成并签发证书（最多 5 分钟）
6. **保存证书 + 清理 DNS** → 存储 fullchain.pem + privkey.pem 到本地

## 部署流程

1. SSH 连接服务器（paramiko）
2. 备份旧证书
3. SFTP 上传新证书和私钥
4. 设置文件权限（证书: 644，私钥: 600）
5. `nginx -t` 配置验证
6. 重载 nginx（失败时自动回滚）

## 项目结构

```
get-ssl-ali/
├── get-ssl-ali/                    # 技能包（可安装到 .claude/skills/）
│   ├── SKILL.md                    # Claude Code 技能定义
│   ├── pyproject.toml
│   ├── config/
│   │   ├── config.example.yaml     # 配置示例
│   │   └── config.yaml             # 实际配置（已 gitignore）
│   ├── certs/                      # 证书存储（已 gitignore）
│   └── scripts/aliyun_ssl_manager/
│       ├── __main__.py             # python -m 入口
│       ├── cli.py                  # 命令行参数解析
│       ├── config.py               # YAML 配置加载 + 环境变量替换
│       ├── models.py               # 数据模型
│       ├── api/
│       │   ├── acme_client.py      # ACME v2 协议（Let's Encrypt）
│       │   ├── cas_client.py       # 阿里云 CAS API（只读，兼容旧版）
│       │   └── dns_client.py       # 阿里云 DNS API
│       ├── core/
│       │   ├── cert_manager.py     # ACME 6 步流程编排
│       │   ├── deployer.py         # SSH/SFTP 部署
│       │   └── validator.py        # DNS 验证管理
│       └── utils/
│           ├── logger.py           # 日志工具
│           └── retry.py            # 轮询重试工具
├── LICENSE
├── README.md
└── README_EN.md
```

## 参与贡献

欢迎提交 Issue 和 Pull Request！

1. Fork 本仓库
2. 创建功能分支 (`git checkout -b feature/awesome-feature`)
3. 提交更改 (`git commit -m 'feat: 添加某个功能'`)
4. 推送到分支 (`git push origin feature/awesome-feature`)
5. 发起 Pull Request

## 许可证

本项目基于 MIT 许可证开源，详见 [LICENSE](LICENSE) 文件。
