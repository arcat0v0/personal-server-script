# Server Initialization Script

一个用于快速初始化服务器的自动化脚本，帮助你在几分钟内完成服务器的基础配置。

## 功能特性

- ✅ **系统支持** - 支持 Debian、Ubuntu 和 Alpine Linux 系统
- 🔧 **系统配置** - 自动修复 hostname 解析问题
- 🔒 **安全加固** - 禁用 root 登录，强制使用 SSH 密钥认证
- 🛡️ **防火墙配置** - 自动配置 UFW 防火墙，只开放必要端口
- 🚨 **入侵防御** - 集成 CrowdSec 防御 SSH 暴力破解和其他攻击
- 👤 **用户管理** - 自动创建 sudo 用户，配置无密码 sudo 权限
- 👥 **多用户支持** - 支持创建额外用户，可单独配置 sudo 权限
- 🔑 **SSH 密钥** - 从 GitHub 自动导入 SSH 公钥，支持国内网络自动切换镜像
- 📦 **系统更新** - 快速更新系统到最新版本
- 🐚 **Shell 优化** - 安装 zsh 和 oh-my-zsh，配置实用插件
- ✨ **Starship 提示符** - 安装并配置 starship 提示符，使用 plain-text-symbols 预设
- 🔧 **Direnv 支持** - 安装 direnv，支持目录级环境变量管理
- 📡 **Mosh 支持** - 安装 mosh，提供更稳定的远程连接体验
- 🚀 **BBR 加速** - 自动检测并启用 BBR 拥塞控制算法（如果内核支持）
- 🌐 **智能网络检测** - 自动检测国内网络环境，使用 Cloudflare Worker 代理

## 快速开始

### 一键安装

**Debian / Ubuntu：**

```bash
curl -fsSL https://raw.githubusercontent.com/arcat0v0/personal-server-script/main/server-init.sh | sudo bash
```

**Alpine Linux：**

```bash
wget -qO- https://raw.githubusercontent.com/arcat0v0/personal-server-script/main/server-init-alpine.sh | sudo sh
```

### 手动安装

```bash
# 下载脚本
wget https://raw.githubusercontent.com/arcat0v0/personal-server-script/main/server-init.sh

# 赋予执行权限
chmod +x server-init.sh

# 以 root 身份运行（交互式）
sudo ./server-init.sh

# 或使用命令行参数
sudo ./server-init.sh -h  # 查看帮助
```

### 命令行参数

脚本支持以下命令行参数：

```bash
# 查看帮助信息
sudo ./server-init.sh -h

# 启用额外用户创建（会提示输入详细信息）
sudo ./server-init.sh -a

# 直接指定额外用户（格式：username@key_url[:sudo|:nopasswd]，多个用户用分号分隔）
# :sudo     - Sudo 访问（需要密码）
# :nopasswd - Sudo 访问（免密）
sudo ./server-init.sh -u 'alice@https://github.com/alice.keys:nopasswd;bob@https://github.com/bob.keys:sudo;charlie@https://github.com/charlie.keys'
```

**参数说明：**
- `-a, --add-users`: 启用额外用户创建功能，脚本会交互式提示输入用户信息
- `-u, --users`: 直接指定额外用户信息，格式为 `username@key_url[:sudo|:nopasswd]`
  - `username`: 用户名
  - `@`: 分隔符（使用 @ 避免与 URL 中的冒号冲突）
  - `key_url`: SSH 密钥 URL（如 `https://github.com/username.keys`）
  - `:sudo`: 可选，表示该用户拥有需密码的 sudo 权限
  - `:nopasswd`: 可选，表示该用户拥有免密 sudo 权限
  - 多个用户用分号 `;` 分隔
- `-h, --help`: 显示帮助信息

## 详细说明

### 系统要求

- 操作系统：Debian、Ubuntu 或 Alpine Linux
  - Debian/Ubuntu：使用 `server-init.sh`
  - Alpine：使用 `server-init-alpine.sh`
- 权限：需要 root 权限
- 网络：需要互联网连接
- 内核：建议 4.9+ 以支持 BBR

### 脚本功能详解

#### 1. 系统检测与配置
- 自动检测操作系统类型和版本
- 修复 hostname 解析问题，避免 sudo 警告
- 自动备份 `/etc/hosts` 文件
- 执行完整的系统更新（update、upgrade、dist-upgrade）
- 清理不需要的软件包

#### 2. 用户配置

**主用户（arcat）：**
- 创建用户名为 `arcat` 的新用户
- 添加到 sudo 组
- 配置无密码 sudo 权限
- 从 GitHub 导入 SSH 公钥（https://github.com/arcat0v0.keys）

**额外用户（可选）：**
- 支持创建多个额外用户
- 每个用户拥有独立的账户和 home 目录
- 可为每个用户单独配置 sudo 权限（需密码或免密）
- 从指定的 URL 导入各自的 SSH 公钥
- 支持交互式输入或命令行参数指定
- 如果用户已存在，会更新其 SSH 密钥

#### 3. SSH 安全加固
- 禁用 root 用户 SSH 登录
- 禁用密码认证
- 启用公钥认证
- 自动备份原始 SSH 配置文件

#### 4. Shell 环境优化

**Zsh 和 Oh-My-Zsh：**
安装并配置 zsh 和 oh-my-zsh，包含以下插件：
- `git` - Git 命令别名和提示
- `sudo` - 按两次 ESC 在命令前添加 sudo
- `zsh-autosuggestions` - 命令自动建议
- `zsh-syntax-highlighting` - 语法高亮
- `colored-man-pages` - 彩色 man 页面
- `command-not-found` - 命令未找到时的友好提示

**Starship 提示符：**
- 安装 starship 跨 shell 提示符
- 使用 plain-text-symbols 预设配置
- 提供美观且信息丰富的命令行提示

**Direnv：**
- 安装 direnv 环境变量管理工具
- 支持目录级别的环境变量自动加载
- 自动配置 zsh hook

#### 5. Mosh 安装
- 安装 mosh（Mobile Shell）提供更稳定的远程连接
- 支持断线重连、网络切换等场景
- 使用 UDP 端口 60000-61000

#### 6. UFW 防火墙配置
- 自动安装和配置 UFW（Uncomplicated Firewall）
- **如果 UFW 已激活，将保留现有规则，并确保 SSH、Mosh 端口开放。**
- 自动检测 SSH 端口并确保其开放
- 设置默认策略：拒绝所有入站连接，允许所有出站连接（仅当 UFW 未激活时重置）
- 开放必要端口：
  - SSH（默认 22，或从配置文件检测）
  - Mosh（60000-61000/UDP）
  - **HTTP（80）和 HTTPS（443）端口默认被注释，如需启用请取消注释脚本中的相关行。**
- 显示防火墙状态和规则

#### 7. CrowdSec 入侵防御系统
- 自动安装和配置 CrowdSec
- 安装 SSH 防护场景集合
- 安装 Linux 基础防护集合
- 配置防火墙 bouncer（与 iptables 集成）
- 自动检测和阻止恶意行为：
  - SSH 暴力破解攻击
  - 端口扫描
  - 其他可疑活动
- 与全球威胁情报网络共享和接收威胁信息
- 提供实时监控和告警

**CrowdSec 常用命令：**
```bash
# 查看告警
sudo cscli alerts list

# 查看当前封禁的 IP
sudo cscli decisions list

# 查看指标统计
sudo cscli metrics

# 查看已安装的场景
sudo cscli scenarios list

# 查看已安装的集合
sudo cscli collections list

# 手动封禁 IP
sudo cscli decisions add --ip 1.2.3.4 --duration 4h --reason "manual ban"

# 解封 IP
sudo cscli decisions delete --ip 1.2.3.4
```

#### 8. BBR 加速
- 检测内核版本是否支持 BBR（需要 4.9+）
- 检测 BBR 模块是否可用
- 自动启用 BBR 拥塞控制算法
- 配置 fq 队列调度算法

## Cloudflare Worker 配置（可选）

为了在国内网络环境下更好地访问 GitHub SSH 密钥，你可以部署一个 Cloudflare Worker 作为代理。

### 部署步骤

1. 登录 [Cloudflare Dashboard](https://dash.cloudflare.com/)
2. 进入 Workers & Pages
3. 创建新的 Worker
4. 复制 `cloudflare-worker.js` 的内容到 Worker 编辑器
5. 部署 Worker 并配置自定义域名

**本项目已配置的 Worker URL**：`https://arcat_keys.xvx.rs`

如果你想使用自己的 Worker，可以修改 `server-init.sh` 中的 `cf_worker_url` 变量：

```bash
# 在 import_ssh_keys() 函数中找到这一行
local cf_worker_url="https://arcat-keys.xvx.rs"
# 替换为你的 Worker URL
```

### 工作原理

脚本会自动检测网络环境：

1. **检测方法**：
   - 尝试快速连接 GitHub（3秒超时）
   - 检查系统时区是否为中国时区
   - 检测是否能访问中国常用 DNS 服务器

2. **智能切换**：
   - 如果检测到国内网络，优先使用 Cloudflare Worker
   - 如果主要源失败，自动尝试备用源
   - 确保密钥文件不为空

3. **双重保障**：
   - GitHub 直连 ⇄ Cloudflare Worker 代理
   - 任一方式失败会自动切换到另一方式

## ECS 抢占式实例保活脚本

`aliyun-ecs-keepalive.py` 用于阿里云 ECS 抢占式实例的保活与流量监控。通过 CDT API 查询当前月流量，低于阈值则启动实例，超过阈值则停止实例，适合通过 crontab 定时调用。

### 依赖安装

推荐使用 [uv](https://github.com/astral-sh/uv) 安装依赖：

```bash
uv sync
```

也可以使用 pip：

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install aliyun-python-sdk-core aliyun-python-sdk-ecs
```

### 环境变量配置

| 环境变量 | 说明 | 默认值 |
|---|---|---|
| `ALIYUN_ACCESS_KEY_ID` | AccessKey ID | 必填 |
| `ALIYUN_ACCESS_KEY_SECRET` | AccessKey Secret | 必填 |
| `ALIYUN_REGION_ID` | 区域 ID | `cn-hongkong` |
| `ALIYUN_ECS_INSTANCE_ID` | ECS 实例 ID | 必填 |
| `TRAFFIC_THRESHOLD_GB` | 流量阈值 (GB) | `180` |

### 命令行参数

```bash
# 查看帮助
python aliyun-ecs-keepalive.py --help

# 自动模式：根据流量自动启停实例
python aliyun-ecs-keepalive.py

# 仅查询流量和实例状态，不执行操作
python aliyun-ecs-keepalive.py --check

# 强制启动实例（忽略流量判断）
python aliyun-ecs-keepalive.py --start

# 强制停止实例（忽略流量判断）
python aliyun-ecs-keepalive.py --stop

# 通过命令行参数覆盖环境变量
python aliyun-ecs-keepalive.py --access-key-id YOUR_KEY --access-key-secret YOUR_SECRET --instance-id i-xxx
```

### Crontab 配置示例

```bash
# 编辑 crontab
crontab -e

# 每 5 分钟检查一次，自动启停实例
*/5 * * * * ALIYUN_ACCESS_KEY_ID=xxx ALIYUN_ACCESS_KEY_SECRET=xxx ALIYUN_ECS_INSTANCE_ID=i-xxx /usr/bin/python3 /path/to/aliyun-ecs-keepalive.py >> /var/log/ecs-keepalive.log 2>&1
```

也可以将环境变量写入文件，配合 `env` 使用：

```bash
# /etc/ecs-keepalive.env
ALIYUN_ACCESS_KEY_ID=xxx
ALIYUN_ACCESS_KEY_SECRET=xxx
ALIYUN_ECS_INSTANCE_ID=i-xxx

# crontab 中引用
*/5 * * * * env $(cat /etc/ecs-keepalive.env | xargs) /usr/bin/python3 /path/to/aliyun-ecs-keepalive.py >> /var/log/ecs-keepalive.log 2>&1
```

## 自定义配置

如果你需要修改默认配置，可以编辑脚本中的以下部分：

- **主用户名**：修改 `username="arcat"` 为你想要的用户名（在 `create_user()` 和 `import_ssh_keys()` 函数中）
- **GitHub 用户**：修改 `github_user="arcat0v0"` 为你的 GitHub 用户名
- **Cloudflare Worker URL**：修改 `cf_worker_url` 为你的 Worker 地址
- **zsh 插件**：在 `install_zsh()` 函数中添加或删除插件
- **额外用户**：使用 `-u` 参数或交互式提示添加额外用户

## 贡献

欢迎提交 Issue 和 Pull Request！

## 许可证

MIT License

## 作者

[@arcat0v0](https://github.com/arcat0v0)
