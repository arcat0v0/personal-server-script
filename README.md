# Server Initialization Script

一个用于快速初始化 Debian/Ubuntu 服务器的自动化脚本，帮助你在几分钟内完成服务器的基础配置。

## 功能特性

- ✅ **系统支持** - 支持 Debian 和 Ubuntu 系统
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

```bash
curl -fsSL https://raw.githubusercontent.com/arcat0v0/personal-server-script/main/server-init.sh | sudo bash
```

或使用 wget：

```bash
wget -qO- https://raw.githubusercontent.com/arcat0v0/personal-server-script/main/server-init.sh | sudo bash
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

# 直接指定额外用户（格式：username@key_url[:sudo]，多个用户用分号分隔）
sudo ./server-init.sh -u 'alice@https://github.com/alice.keys:sudo;bob@https://github.com/bob.keys'
```

**参数说明：**
- `-a, --add-users`: 启用额外用户创建功能，脚本会交互式提示输入用户信息
- `-u, --users`: 直接指定额外用户信息，格式为 `username@key_url[:sudo]`
  - `username`: 用户名
  - `@`: 分隔符（使用 @ 避免与 URL 中的冒号冲突）
  - `key_url`: SSH 密钥 URL（如 `https://github.com/username.keys`）
  - `:sudo`: 可选，表示该用户拥有 sudo 权限
  - 多个用户用分号 `;` 分隔
- `-h, --help`: 显示帮助信息

## 详细说明

### 系统要求

- 操作系统：Debian 或 Ubuntu
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
- 可为每个用户单独配置 sudo 权限
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
- 自动检测 SSH 端口并确保其开放
- 设置默认策略：拒绝所有入站连接，允许所有出站连接
- 开放必要端口：
  - SSH（默认 22，或从配置文件检测）
  - HTTP（80）
  - HTTPS（443）
  - Mosh（60000-61000/UDP）
- 自动备份和重置防火墙配置
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

## 安全提示

⚠️ **重要：** 脚本执行完成后，请务必在关闭当前 SSH 会话之前：

1. 打开一个新的终端窗口
2. 使用新创建的 `arcat` 用户测试 SSH 登录
3. 确认可以正常登录并使用 sudo
4. 如果创建了额外用户，也要测试这些用户的登录
5. 确认无误后再关闭原有的 root 会话

```bash
# 在新终端测试主用户 SSH 登录
ssh arcat@your-server-ip

# 或使用 mosh 连接（推荐）
mosh arcat@your-server-ip

# 测试 sudo 权限
sudo whoami

# 如果创建了额外用户，也要测试
ssh alice@your-server-ip
ssh bob@your-server-ip
```

**多用户管理建议：**
- 为不同的团队成员创建独立的用户账户
- 根据实际需要分配 sudo 权限，遵循最小权限原则
- 定期审查用户列表和权限配置
- 使用 `last` 命令查看用户登录历史
- 使用 `w` 或 `who` 命令查看当前登录用户

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

## 自定义配置

如果你需要修改默认配置，可以编辑脚本中的以下部分：

- **主用户名**：修改 `username="arcat"` 为你想要的用户名（在 `create_user()` 和 `import_ssh_keys()` 函数中）
- **GitHub 用户**：修改 `github_user="arcat0v0"` 为你的 GitHub 用户名
- **Cloudflare Worker URL**：修改 `cf_worker_url` 为你的 Worker 地址
- **zsh 插件**：在 `install_zsh()` 函数中添加或删除插件
- **额外用户**：使用 `-u` 参数或交互式提示添加额外用户

### 额外用户配置示例

**场景 1：团队协作服务器**
```bash
# 创建开发团队成员账户，部分成员有 sudo 权限
sudo ./server-init.sh -u 'alice@https://github.com/alice.keys:sudo;bob@https://github.com/bob.keys;charlie@https://github.com/charlie.keys:sudo'
```

**场景 2：个人多账户**
```bash
# 为自己创建多个账户用于不同用途
sudo ./server-init.sh -u 'work@https://github.com/mywork.keys:sudo;personal@https://github.com/mypersonal.keys'
```

**场景 3：临时访客账户**
```bash
# 为临时访客创建无 sudo 权限的账户
sudo ./server-init.sh -u 'guest@https://github.com/guest.keys'
```

## 故障排除

### 无法连接到服务器
- 确保在测试新用户登录成功之前不要关闭原有的 SSH 会话
- 检查 SSH 公钥是否正确导入到 `~/.ssh/authorized_keys`
- 检查 SSH 服务是否正常运行：`systemctl status ssh`

### BBR 未启用
- 检查内核版本：`uname -r`（需要 4.9+）
- 检查 BBR 模块：`lsmod | grep bbr`
- 手动验证：`sysctl net.ipv4.tcp_congestion_control`

### oh-my-zsh 安装失败
- 检查网络连接
- 手动安装：`sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"`

### Mosh 连接问题
- 确保防火墙开放 UDP 端口 60000-61000
- 检查 mosh 是否安装：`which mosh`
- 本地也需要安装 mosh 客户端才能使用

### SSH 密钥下载失败
- 检查网络连接是否正常
- 如果在国内，确保已配置 Cloudflare Worker
- 手动测试密钥 URL：`curl -I https://github.com/arcat0v0.keys`
- 检查 GitHub 用户名是否正确
- 验证 Worker 是否正常工作：`curl https://your-worker-url`

### 额外用户创建失败
- **用户名冲突**：检查用户是否已存在 `id username`
- **密钥 URL 无效**：确保 URL 格式正确且可访问
- **权限问题**：确保以 root 身份运行脚本
- **格式错误**：检查参数格式是否正确
  - 正确格式：`username@key_url[:sudo]`
  - 多个用户用分号分隔：`user1@url1;user2@url2:sudo`
  - 示例：`alice@https://github.com/alice.keys:sudo`
- **查看创建的用户**：`cat /etc/passwd | grep -E "arcat|alice|bob"`
- **检查 SSH 密钥**：`cat /home/username/.ssh/authorized_keys`
- **验证 sudo 权限**：`sudo -l -U username`

## 贡献

欢迎提交 Issue 和 Pull Request！

## 许可证

MIT License

## 作者

[@arcat0v0](https://github.com/arcat0v0)
