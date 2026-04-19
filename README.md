# Personal Server Script Collection

一个面向个人服务器日常运维的脚本集合：初始化、安全加固、端口转发、以及云实例保活。

## 脚本总览

| 脚本 | 作用 | 适用环境 |
|---|---|---|
| `server-init.sh` | Debian/Ubuntu 一键初始化（用户、SSH、安全、防火墙、常用工具） | Debian / Ubuntu |
| `server-init-alpine.sh` | Alpine 一键初始化（OpenRC + nftables） | Alpine Linux |
| `nft-port-forward.sh` | nftables 一键端口转发（交互菜单 + 自动持久化） | Linux（systemd / OpenRC） |
| `aliyun-ecs-keepalive.py` | 阿里云 ECS 抢占式实例按流量阈值自动启停 | Python 3 |
| `cloudflare-worker.js` | GitHub Keys 代理 Worker（国内网络可选） | Cloudflare Workers |
| `config-template.dae` | dae 配置模板（CN 模式下使用） | dae |

## 快速开始

### 1) Debian / Ubuntu 初始化

```bash
curl -fsSL https://raw.githubusercontent.com/arcat0v0/personal-server-script/main/server-init.sh | sudo bash
```

### 2) Alpine 初始化

```bash
wget -qO- https://raw.githubusercontent.com/arcat0v0/personal-server-script/main/server-init-alpine.sh | sudo sh
```

### 3) nftables 端口转发

```bash
wget https://raw.githubusercontent.com/arcat0v0/personal-server-script/main/nft-port-forward.sh
chmod +x nft-port-forward.sh
sudo ./nft-port-forward.sh
```

### 4) ECS 保活脚本

```bash
uv sync
python aliyun-ecs-keepalive.py --help
```

## `server-init*` 功能清单

- 系统更新与基础工具安装
- 国内网络下自动切换 APT / APK 官方仓库到国内镜像
- 新建用户并导入 SSH 公钥
- SSH 安全加固（禁 root、禁密码登录）
- 防火墙配置（Debian/Ubuntu 支持 `ufw` 或 `nftables`，Alpine 使用 `nftables`）
- CrowdSec 安装与基础接入
- zsh / oh-my-zsh / starship / direnv / mosh
- 内核支持时自动启用 BBR

## 常用参数

### `server-init.sh`（Debian/Ubuntu）

```bash
sudo ./server-init.sh -h
sudo ./server-init.sh -a
sudo ./server-init.sh -u 'alice@https://github.com/alice.keys:nopasswd;bob@https://github.com/bob.keys:sudo'
sudo ./server-init.sh --firewall nftables
sudo ./server-init.sh --cn --dae-sub "https://example.com/subscription"
```

- `-a, --add-users`: 交互式添加额外用户
- `-u, --users`: 通过参数直接传入多个用户
- `--firewall`: `nftables` 或 `ufw`
- `--cn`: 强制启用中国网络优化地址
- `--dae-sub`: 可选，dae 配置里的订阅地址
- 国内源默认使用 `USTC`，可通过 `CN_MIRROR_PROVIDER=ustc|tuna|aliyun` 切换
- 也可直接覆盖 `CN_APT_MIRROR_BASE`、`CN_APT_SECURITY_MIRROR_BASE`、`CN_APT_PORTS_MIRROR_BASE`

### `server-init-alpine.sh`（Alpine）

```bash
sudo ./server-init-alpine.sh -h
sudo ./server-init-alpine.sh -a
sudo ./server-init-alpine.sh -u 'alice@https://github.com/alice.keys:nopasswd'
sudo ./server-init-alpine.sh --cn --dae-sub "https://example.com/subscription"
```

- 支持 `-a`、`-u`、`--cn`、`--dae-sub`
- 防火墙默认使用 nftables
- `--dae-sub` 为可选；未提供时会跳过 dae，但仍继续完整初始化
- 国内源默认使用 `USTC`，可通过 `CN_MIRROR_PROVIDER=ustc|tuna|aliyun` 或 `CN_APK_MIRROR_BASE` 覆盖

## 国内镜像说明

- `--cn` 或 `FORCE_CN=1` 时，会优先把系统包管理器官方仓库切到国内镜像，再执行 `apt update` / `apk update`
- `CN` 模式不会再跳过防火墙、CrowdSec、zsh、mosh、BBR 等初始化步骤；仅 `dae` 订阅仍为可选
- `CN` 模式下，`oh-my-zsh` 及其常用插件会优先走国内 Git 镜像；包管理器安装则优先走已切换的国内软件源
- 未强制 `--cn` 时，脚本会在装好 `curl` 后做一次 CN 网络探测；探测到国内环境后，也会在系统更新前切换镜像
- Debian/Ubuntu 只替换官方仓库 URL，保留现有 suites / components，不重写第三方源
- Alpine 会同步替换 `/etc/apk/repositories`，并让后续追加的 `edge` 仓库也沿用同一镜像基址
- 网络相关命令已加入超时/重试控制，可按需通过 `NETWORK_RETRIES`、`NETWORK_MAX_TIME`、`PACKAGE_COMMAND_TIMEOUT`、`INSTALLER_COMMAND_TIMEOUT`、`GIT_CLONE_TIMEOUT` 覆盖默认值

## `nft-port-forward.sh` 用法

交互模式（默认）：

```bash
sudo ./nft-port-forward.sh
```

可选命令：

```bash
sudo ./nft-port-forward.sh --apply-once
sudo ./nft-port-forward.sh --daemon
sudo ./nft-port-forward.sh --uninstall
```

说明：

- 转发规则保存于 `/etc/dnat-nft/conf`
- 自动按系统生成并启用守护服务（systemd: `dnat-nft.service`，OpenRC: `/etc/init.d/dnat-nft`）
- 每 60 秒刷新域名解析并重建 nftables 规则
- 卸载会清理 service、规则表与配置目录

## `aliyun-ecs-keepalive.py` 用法

### 环境变量

| 环境变量 | 说明 | 默认值 |
|---|---|---|
| `ALIYUN_ACCESS_KEY_ID` | AccessKey ID | 必填 |
| `ALIYUN_ACCESS_KEY_SECRET` | AccessKey Secret | 必填 |
| `ALIYUN_REGION_ID` | 区域 ID | `cn-hongkong` |
| `ALIYUN_ECS_INSTANCE_ID` | ECS 实例 ID | 必填 |
| `TRAFFIC_THRESHOLD_GB` | 月流量阈值（GB） | `180` |

### 常用命令

```bash
python aliyun-ecs-keepalive.py --help
python aliyun-ecs-keepalive.py --check
python aliyun-ecs-keepalive.py --start
python aliyun-ecs-keepalive.py --stop
```

## Cloudflare Worker（可选）

`cloudflare-worker.js` 可作为 GitHub keys 的代理入口，用于国内网络场景下提升稳定性。部署后将 Worker 地址填入初始化脚本中对应变量即可。

## 目录建议

- 生产环境建议保留：`server-init*.sh`、`nft-port-forward.sh`、`aliyun-ecs-keepalive.py`
- 测试辅助脚本：`test-alpine-init.sh`、`test-validate.sh`

## 许可证

MIT License

## 作者

[@arcat0v0](https://github.com/arcat0v0)
