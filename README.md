# Server Initialization Script

一个用于快速初始化 Debian/Ubuntu 服务器的自动化脚本，帮助你在几分钟内完成服务器的基础配置。

## 功能特性

- ✅ **系统支持** - 支持 Debian 和 Ubuntu 系统
- 🔒 **安全加固** - 禁用 root 登录，强制使用 SSH 密钥认证
- 👤 **用户管理** - 自动创建 sudo 用户，配置无密码 sudo 权限
- 🔑 **SSH 密钥** - 从 GitHub 自动导入 SSH 公钥，支持国内网络自动切换镜像
- 📦 **系统更新** - 快速更新系统到最新版本
- 🐚 **Shell 优化** - 安装 zsh 和 oh-my-zsh，配置实用插件
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

# 以 root 身份运行
sudo ./server-init.sh
```

## 详细说明

### 系统要求

- 操作系统：Debian 或 Ubuntu
- 权限：需要 root 权限
- 网络：需要互联网连接
- 内核：建议 4.9+ 以支持 BBR

### 脚本功能详解

#### 1. 系统检测与更新
- 自动检测操作系统类型和版本
- 执行完整的系统更新（update、upgrade、dist-upgrade）
- 清理不需要的软件包

#### 2. 用户配置
- 创建用户名为 `arcat` 的新用户
- 添加到 sudo 组
- 配置无密码 sudo 权限
- 从 GitHub 导入 SSH 公钥（https://github.com/arcat0v0.keys）

#### 3. SSH 安全加固
- 禁用 root 用户 SSH 登录
- 禁用密码认证
- 启用公钥认证
- 自动备份原始 SSH 配置文件

#### 4. Shell 环境优化
安装并配置 zsh 和 oh-my-zsh，包含以下插件：
- `git` - Git 命令别名和提示
- `sudo` - 按两次 ESC 在命令前添加 sudo
- `zsh-autosuggestions` - 命令自动建议
- `zsh-syntax-highlighting` - 语法高亮
- `colored-man-pages` - 彩色 man 页面
- `command-not-found` - 命令未找到时的友好提示

#### 5. Mosh 安装
- 安装 mosh（Mobile Shell）提供更稳定的远程连接
- 自动配置防火墙规则（如果启用了 ufw）
- 支持断线重连、网络切换等场景
- 使用 UDP 端口 60000-61000

#### 6. BBR 加速
- 检测内核版本是否支持 BBR（需要 4.9+）
- 检测 BBR 模块是否可用
- 自动启用 BBR 拥塞控制算法
- 配置 fq 队列调度算法

## 安全提示

⚠️ **重要：** 脚本执行完成后，请务必在关闭当前 SSH 会话之前：

1. 打开一个新的终端窗口
2. 使用新创建的 `arcat` 用户测试 SSH 登录
3. 确认可以正常登录并使用 sudo
4. 确认无误后再关闭原有的 root 会话

```bash
# 在新终端测试 SSH 登录
ssh arcat@your-server-ip

# 或使用 mosh 连接（推荐）
mosh arcat@your-server-ip

# 测试 sudo 权限
sudo whoami
```

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

- **用户名**：修改 `username="arcat"` 为你想要的用户名
- **GitHub 用户**：修改 `github_user="arcat0v0"` 为你的 GitHub 用户名
- **Cloudflare Worker URL**：修改 `cf_worker_url` 为你的 Worker 地址
- **zsh 插件**：在 `install_zsh()` 函数中添加或删除插件

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

## 贡献

欢迎提交 Issue 和 Pull Request！

## 许可证

MIT License

## 作者

[@arcat0v0](https://github.com/arcat0v0)
