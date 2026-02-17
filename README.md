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
- `--dae-sub`: dae 配置里的订阅地址

### `server-init-alpine.sh`（Alpine）

```bash
sudo ./server-init-alpine.sh -h
sudo ./server-init-alpine.sh -a
sudo ./server-init-alpine.sh -u 'alice@https://github.com/alice.keys:nopasswd'
sudo ./server-init-alpine.sh --cn --dae-sub "https://example.com/subscription"
```

- 支持 `-a`、`-u`、`--cn`、`--dae-sub`
- 防火墙默认使用 nftables

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
