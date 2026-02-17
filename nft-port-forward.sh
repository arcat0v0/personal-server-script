#!/bin/sh

set -e

BASE_DIR="/etc/dnat-nft"
CONF_FILE="${BASE_DIR}/conf"
RULES_FILE="${BASE_DIR}/rules.nft"
STATE_FILE="${BASE_DIR}/resolved"
INSTALLED_SCRIPT="/usr/local/bin/dnat-nft"
SERVICE_NAME="dnat-nft"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
OPENRC_SERVICE_FILE="/etc/init.d/${SERVICE_NAME}"
TABLE_NAME="dnat_nft"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

need_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log_error "请使用 root 运行该脚本"
        exit 1
    fi
}

has_cmd() {
    command -v "$1" >/dev/null 2>&1
}

init_service_manager() {
    if has_cmd systemctl; then
        SERVICE_MANAGER="systemd"
        SERVICE_ENABLE() { systemctl enable "$1" >/dev/null 2>&1; }
        SERVICE_START() { systemctl start "$1" >/dev/null 2>&1; }
        SERVICE_RESTART() { systemctl restart "$1" >/dev/null 2>&1; }
        SERVICE_STOP() { systemctl stop "$1" >/dev/null 2>&1; }
        SERVICE_DISABLE() { systemctl disable "$1" >/dev/null 2>&1; }
    elif has_cmd rc-service; then
        SERVICE_MANAGER="openrc"
        SERVICE_ENABLE() { rc-update add "$1" default >/dev/null 2>&1; }
        SERVICE_START() { rc-service "$1" start >/dev/null 2>&1; }
        SERVICE_RESTART() { rc-service "$1" restart >/dev/null 2>&1 || rc-service "$1" start >/dev/null 2>&1; }
        SERVICE_STOP() { rc-service "$1" stop >/dev/null 2>&1; }
        SERVICE_DISABLE() { rc-update del "$1" default >/dev/null 2>&1; }
    else
        SERVICE_MANAGER="none"
        SERVICE_ENABLE() { return 1; }
        SERVICE_START() { return 1; }
        SERVICE_RESTART() { return 1; }
        SERVICE_STOP() { return 1; }
        SERVICE_DISABLE() { return 1; }
    fi
}

ensure_base() {
    mkdir -p "${BASE_DIR}"
    touch "${CONF_FILE}"
}

install_dependency() {
    local pkg="$1"
    if has_cmd apt-get; then
        apt-get update -y >/dev/null 2>&1 || true
        apt-get install -y "$pkg" >/dev/null 2>&1 || true
    elif has_cmd apt; then
        apt update -y >/dev/null 2>&1 || true
        apt install -y "$pkg" >/dev/null 2>&1 || true
    elif has_cmd dnf; then
        dnf install -y "$pkg" >/dev/null 2>&1 || true
    elif has_cmd yum; then
        yum install -y "$pkg" >/dev/null 2>&1 || true
    elif has_cmd apk; then
        apk add --no-cache "$pkg" >/dev/null 2>&1 || true
    fi
}

ensure_deps() {
    if ! has_cmd nft; then
        log_info "正在安装 nftables..."
        install_dependency nftables
    fi

    if ! has_cmd host; then
        log_info "正在安装 DNS 查询工具..."
        if has_cmd apk; then
            install_dependency bind-tools
        else
            install_dependency dnsutils
            install_dependency bind-utils
        fi
    fi

    if ! has_cmd nft; then
        log_error "未找到 nft 命令，请手动安装 nftables 后重试"
        exit 1
    fi

    if ! has_cmd host; then
        log_warn "未找到 host 命令，将仅支持直接使用 IP 作为目标地址"
    fi
}

ensure_ip_forward() {
    if ! grep -q "^net.ipv4.ip_forward=1$" /etc/sysctl.conf 2>/dev/null; then
        echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    fi
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
    sysctl -p >/dev/null 2>&1 || true
}

get_local_ip() {
    local ip
    ip=$(ip -o -4 addr list | grep -Ev '\s(docker|lo)' | awk '{print $4}' | cut -d/ -f1 | \
        grep -Ev '(^127\.)|(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^192\.168\.)' | head -n1)
    if [ -z "$ip" ]; then
        ip=$(ip -o -4 addr list | grep -Ev '\s(docker|lo)' | awk '{print $4}' | cut -d/ -f1 | head -n1)
    fi
    echo "$ip"
}

resolve_host() {
    local target="$1"
    if echo "$target" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$'; then
        echo "$target"
        return 0
    fi

    if has_cmd host; then
        host -t a "$target" 2>/dev/null | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -n1
        return 0
    fi

    if has_cmd getent; then
        getent ahostsv4 "$target" 2>/dev/null | awk 'NR==1 {print $1; exit}'
        return 0
    fi

    if has_cmd nslookup; then
        nslookup "$target" 2>/dev/null | awk '/^Address[[:space:]]+[0-9]*:[[:space:]]/ {print $NF; exit}'
        return 0
    fi

    if has_cmd dig; then
        dig +short A "$target" 2>/dev/null | awk 'NR==1 {print $1; exit}'
        return 0
    fi

    return 1
}

can_resolve_dns() {
    has_cmd host || has_cmd getent || has_cmd nslookup || has_cmd dig
}

valid_port() {
    local port="$1"
    if ! echo "$port" | grep -Eq '^[0-9]+$'; then
        return 1
    fi
    if [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        return 1
    fi
    return 0
}

render_rules() {
    local local_ip
    local_ip="$(get_local_ip)"

    if [ -z "$local_ip" ]; then
        log_error "无法检测本机 IPv4 地址"
        return 1
    fi

    : > "${STATE_FILE}"

    {
        echo "flush table ip ${TABLE_NAME}"
        echo "table ip ${TABLE_NAME} {"
        echo "  chain prerouting {"
        echo "    type nat hook prerouting priority dstnat; policy accept;"
        echo "  }"
        echo "  chain postrouting {"
        echo "    type nat hook postrouting priority srcnat; policy accept;"
        echo "  }"
        echo "}"
    } > "${RULES_FILE}"

    while IFS= read -r line; do
        [ -z "$line" ] && continue
        local_port="${line%%>*}"
        right="${line#*>}"
        remote_host="${right%:*}"
        remote_port="${right##*:}"

        if ! valid_port "$local_port" || ! valid_port "$remote_port"; then
            log_warn "跳过无效规则: $line"
            continue
        fi

        remote_ip="$(resolve_host "$remote_host")"
        if [ -z "$remote_ip" ]; then
            log_warn "目标地址解析失败，跳过: $remote_host"
            continue
        fi

        echo "${local_port}>${remote_host}:${remote_port}=${remote_ip}" >> "${STATE_FILE}"

        {
            echo "add rule ip ${TABLE_NAME} prerouting tcp dport ${local_port} dnat to ${remote_ip}:${remote_port} comment \"DNAT TCP ${local_port}->${remote_host}:${remote_port}\""
            echo "add rule ip ${TABLE_NAME} prerouting udp dport ${local_port} dnat to ${remote_ip}:${remote_port} comment \"DNAT UDP ${local_port}->${remote_host}:${remote_port}\""
            echo "add rule ip ${TABLE_NAME} postrouting ip daddr ${remote_ip} tcp dport ${remote_port} snat to ${local_ip} comment \"SNAT TCP ${remote_host}:${remote_port}\""
            echo "add rule ip ${TABLE_NAME} postrouting ip daddr ${remote_ip} udp dport ${remote_port} snat to ${local_ip} comment \"SNAT UDP ${remote_host}:${remote_port}\""
        } >> "${RULES_FILE}"
    done < "${CONF_FILE}"
}

apply_rules() {
    nft -f "${RULES_FILE}"
}

setup_service() {
    local src_path
    src_path="$(readlink -f "$0")"
    cp "$src_path" "${INSTALLED_SCRIPT}"
    chmod +x "${INSTALLED_SCRIPT}"

    init_service_manager

    if [ "$SERVICE_MANAGER" = "systemd" ]; then
        cat > "${SERVICE_FILE}" <<EOF
[Unit]
Description=nftables DNAT auto updater
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${INSTALLED_SCRIPT} --daemon
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

        systemctl daemon-reload >/dev/null 2>&1 || true
        SERVICE_ENABLE "${SERVICE_NAME}" || true
        SERVICE_RESTART "${SERVICE_NAME}" || SERVICE_START "${SERVICE_NAME}" || true
        return
    fi

    if [ "$SERVICE_MANAGER" = "openrc" ]; then
        cat > "${OPENRC_SERVICE_FILE}" <<EOF
#!/sbin/openrc-run
name="dnat-nft"
description="nftables DNAT auto updater"
command="${INSTALLED_SCRIPT}"
command_args="--daemon"
command_background="yes"
pidfile="/run/\${RC_SVCNAME}.pid"

depend() {
    need net
    after firewall
}
EOF
        chmod +x "${OPENRC_SERVICE_FILE}"
        SERVICE_ENABLE "${SERVICE_NAME}" || true
        SERVICE_RESTART "${SERVICE_NAME}" || SERVICE_START "${SERVICE_NAME}" || true
        return
    fi

    log_warn "未检测到 systemd 或 OpenRC，已跳过服务持久化"
}

run_once() {
    need_root
    ensure_base
    ensure_deps
    ensure_ip_forward
    render_rules
    apply_rules
}

run_daemon() {
    while true; do
        if ! run_once; then
            log_warn "规则更新失败，60 秒后重试"
        fi
        sleep 60
    done
}

list_rules() {
    if [ ! -s "${CONF_FILE}" ]; then
        echo "暂无转发规则"
        return
    fi

    local i=1
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        local_port="${line%%>*}"
        right="${line#*>}"
        remote_host="${right%:*}"
        remote_port="${right##*:}"
        echo "$i) 本地 ${local_port} -> ${remote_host}:${remote_port}"
        i=$((i + 1))
    done < "${CONF_FILE}"
}

add_rule() {
    local local_port="$1"
    local remote_port="$2"
    local remote_host="$3"

    if ! valid_port "$local_port"; then
        log_error "本地端口无效: $local_port"
        return 1
    fi

    if ! valid_port "$remote_port"; then
        log_error "远程端口无效: $remote_port"
        return 1
    fi

    if [ -z "$remote_host" ]; then
        log_error "目标域名/IP 不能为空"
        return 1
    fi

    if ! echo "$remote_host" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$' && ! can_resolve_dns; then
        log_error "当前系统缺少 DNS 解析命令，无法解析域名，请先安装 bind-tools 或直接填写 IP"
        return 1
    fi

    ensure_base
    if grep -qE "^${local_port}>" "${CONF_FILE}"; then
        sed -i "s#^${local_port}>.*#${local_port}>${remote_host}:${remote_port}#" "${CONF_FILE}"
    else
        echo "${local_port}>${remote_host}:${remote_port}" >> "${CONF_FILE}"
    fi

    run_once
    setup_service
    log_info "转发规则已生效: ${local_port} -> ${remote_host}:${remote_port}"
}

remove_rule() {
    local local_port="$1"

    if ! valid_port "$local_port"; then
        log_error "本地端口无效: $local_port"
        return 1
    fi

    if [ ! -f "${CONF_FILE}" ] || ! grep -qE "^${local_port}>" "${CONF_FILE}"; then
        log_warn "端口 ${local_port} 不存在转发规则"
        return 0
    fi

    grep -vE "^${local_port}>" "${CONF_FILE}" > "${CONF_FILE}.tmp"
    mv "${CONF_FILE}.tmp" "${CONF_FILE}"

    run_once
    setup_service
    log_info "已删除端口 ${local_port} 的转发规则"
}

show_nft() {
    if nft list table ip "${TABLE_NAME}" >/dev/null 2>&1; then
        nft list table ip "${TABLE_NAME}"
    else
        log_warn "当前未找到 ${TABLE_NAME} 规则表"
    fi
}

uninstall_all() {
    need_root

    init_service_manager

    if [ "$SERVICE_MANAGER" = "systemd" ]; then
        SERVICE_STOP "${SERVICE_NAME}" || true
        SERVICE_DISABLE "${SERVICE_NAME}" || true
        systemctl daemon-reload >/dev/null 2>&1 || true
    elif [ "$SERVICE_MANAGER" = "openrc" ]; then
        SERVICE_STOP "${SERVICE_NAME}" || true
        SERVICE_DISABLE "${SERVICE_NAME}" || true
    fi

    if has_cmd nft && nft list table ip "${TABLE_NAME}" >/dev/null 2>&1; then
        nft delete table ip "${TABLE_NAME}" >/dev/null 2>&1 || true
    fi

    rm -rf "${BASE_DIR}"
    rm -f "${SERVICE_FILE}"
    rm -f "${OPENRC_SERVICE_FILE}"
    rm -f "${INSTALLED_SCRIPT}"

    log_info "已卸载 dnat-nft 并清理规则"
}

show_help() {
    cat <<EOF
Usage: $0 [OPTIONS]

Options:
  --daemon                 Run as service loop, refresh every 60 seconds
  --apply-once             Resolve domain and apply nftables rules once
  --uninstall              Remove service, rules, and config
  -h, --help               Show help

Run without options to enter interactive mode.
EOF
}

menu() {
    need_root
    ensure_base

    while true; do
        echo ""
        echo "========== nftables 端口转发管理 =========="
        echo "1) 增加转发规则"
        echo "2) 删除转发规则"
        echo "3) 列出所有转发规则"
        echo "4) 查看当前 nftables 规则"
        echo "5) 卸载脚本并清理规则"
        echo "0) 退出"
        echo -n "请选择 [0-5]: "
        read -r choice

        case "$choice" in
            1)
                echo -n "本地端口号: "
                read -r local_port
                echo -n "远程端口号: "
                read -r remote_port
                echo -n "目标域名/IP: "
                read -r remote_host
                add_rule "$local_port" "$remote_port" "$remote_host"
                ;;
            2)
                echo -n "要删除的本地端口号: "
                read -r local_port
                remove_rule "$local_port"
                ;;
            3)
                list_rules
                ;;
            4)
                show_nft
                ;;
            5)
                echo -n "确认卸载并清理所有规则? [y/N]: "
                read -r confirm
                case "$confirm" in
                    y|Y) uninstall_all ;;
                    *) log_info "已取消" ;;
                esac
                ;;
            0)
                exit 0
                ;;
            *)
                log_warn "无效选项"
                ;;
        esac
    done
}

main() {
    case "${1:-}" in
        --daemon)
            run_daemon
            ;;
        --apply-once)
            run_once
            ;;
        --uninstall)
            uninstall_all
            ;;
        -h|--help)
            show_help
            ;;
        "")
            menu
            ;;
        *)
            log_error "未知参数: $1"
            show_help
            exit 1
            ;;
    esac
}

main "$@"
