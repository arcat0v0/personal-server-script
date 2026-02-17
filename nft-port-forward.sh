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
NFT_MAIN_CONF=""
NFT_INCLUDE_DIR="/etc/nftables.d"
NFT_PERSIST_FILE=""

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() {
    printf '%b\n' "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    printf '%b\n' "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    printf '%b\n' "${RED}[ERROR]${NC} $1"
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
    touch "${STATE_FILE}"
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
    if [ -f /etc/sysctl.conf ] && grep -Eq '^net\.ipv4\.ip_forward[[:space:]]*=' /etc/sysctl.conf; then
        sed -i 's/^net\.ipv4\.ip_forward[[:space:]]*=.*/net.ipv4.ip_forward=1/' /etc/sysctl.conf
    elif ! grep -Eq '^net\.ipv4\.ip_forward[[:space:]]*=[[:space:]]*1$' /etc/sysctl.conf 2>/dev/null; then
        echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    fi

    if ! sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1; then
        log_error "启用 net.ipv4.ip_forward 失败"
        return 1
    fi

    if [ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)" != "1" ]; then
        log_error "内核转发未开启: net.ipv4.ip_forward=0"
        return 1
    fi
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
    : > "${STATE_FILE}"

    if nft list table ip "${TABLE_NAME}" >/dev/null 2>&1; then
        echo "delete table ip ${TABLE_NAME}" > "${RULES_FILE}"
    else
        : > "${RULES_FILE}"
    fi

    {
        echo "table ip ${TABLE_NAME} {"
        echo "  chain prerouting {"
        echo "    type nat hook prerouting priority dstnat; policy accept;"
        echo "  }"
        echo "  chain output {"
        echo "    type nat hook output priority dstnat; policy accept;"
        echo "  }"
        echo "  chain postrouting {"
        echo "    type nat hook postrouting priority srcnat; policy accept;"
        echo "  }"
        echo "}"
    } >> "${RULES_FILE}"

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
            echo "add rule ip ${TABLE_NAME} output fib daddr type local tcp dport ${local_port} dnat to ${remote_ip}:${remote_port} comment \"DNAT OUTPUT TCP ${local_port}->${remote_host}:${remote_port}\""
            echo "add rule ip ${TABLE_NAME} output fib daddr type local udp dport ${local_port} dnat to ${remote_ip}:${remote_port} comment \"DNAT OUTPUT UDP ${local_port}->${remote_host}:${remote_port}\""
            echo "add rule ip ${TABLE_NAME} postrouting ip daddr ${remote_ip} tcp dport ${remote_port} masquerade comment \"MASQ TCP ${remote_host}:${remote_port}\""
            echo "add rule ip ${TABLE_NAME} postrouting ip daddr ${remote_ip} udp dport ${remote_port} masquerade comment \"MASQ UDP ${remote_host}:${remote_port}\""
        } >> "${RULES_FILE}"
    done < "${CONF_FILE}"
}

apply_rules() {
    nft -f "${RULES_FILE}"
}

list_forward_base_chains() {
    nft list tables 2>/dev/null | while IFS=' ' read -r kind family table; do
        [ "$kind" = "table" ] || continue
        [ -z "$family" ] && continue
        [ -z "$table" ] && continue

        nft list table "$family" "$table" 2>/dev/null | awk -v family="$family" -v table="$table" '
            $1 == "chain" {
                chain = $2
                sub("\\{$", "", chain)
            }
            $0 ~ /hook[[:space:]]+forward/ {
                if (family == "ip" || family == "ip6" || family == "inet") {
                    print family "|" table "|" chain
                }
            }
        '
    done
}

init_nft_persistence_paths() {
    # Guard: only re-init if BOTH are set (fully initialized)
    if [ -n "$NFT_MAIN_CONF" ] && [ -n "$NFT_PERSIST_FILE" ]; then
        return 0
    fi

    # Reset to ensure clean state
    NFT_MAIN_CONF=""
    NFT_PERSIST_FILE=""
    NFT_INCLUDE_DIR=""

    # Detect main config path
    local alpine_rules_file=""
    if [ -f /etc/conf.d/nftables ]; then
        alpine_rules_file="$(sed -n 's/^[[:space:]]*rules_file=["'"'"']\{0,1\}\([^"'"'"'[:space:]]\+\)["'"'"']\{0,1\}[[:space:]]*$/\1/p' /etc/conf.d/nftables | tail -n1 || true)"
    fi

    if [ -n "$alpine_rules_file" ]; then
        NFT_MAIN_CONF="$alpine_rules_file"
    elif [ -f /etc/nftables.nft ]; then
        NFT_MAIN_CONF="/etc/nftables.nft"
    elif [ -f /etc/nftables.conf ]; then
        NFT_MAIN_CONF="/etc/nftables.conf"
    elif [ -x /sbin/openrc-run ] || [ -d /run/openrc ]; then
        NFT_MAIN_CONF="/etc/nftables.nft"
    else
        NFT_MAIN_CONF="/etc/nftables.conf"
    fi

    # Parse include directory from main config
    local include_path=""
    local include_candidates=""
    local preferred_include=""
    if [ -f "$NFT_MAIN_CONF" ]; then
        include_candidates="$(sed -n 's/^[[:space:]]*include[[:space:]]*"\([^"]*\)".*/\1/p' "$NFT_MAIN_CONF" | grep -E '/\*\.nft$|\.nft$' || true)"

        if [ -n "$include_candidates" ]; then
            preferred_include="$(printf '%s\n' "$include_candidates" | grep -E '/etc/nftables\.d/(\*\.nft|[^/]+\.nft)$' | head -n1 || true)"
            if [ -z "$preferred_include" ]; then
                preferred_include="$(printf '%s\n' "$include_candidates" | grep -Ev '^/var/lib/nftables/(\*\.nft|[^/]+\.nft)$' | head -n1 || true)"
            fi
            if [ -z "$preferred_include" ]; then
                preferred_include="$(printf '%s\n' "$include_candidates" | head -n1 || true)"
            fi
            include_path="$preferred_include"
        fi
    fi

    if [ -n "$include_path" ]; then
        case "$include_path" in
            */*.nft)
                NFT_INCLUDE_DIR="${include_path%/*.nft}"
                ;;
            *.nft)
                NFT_INCLUDE_DIR="$(dirname "$include_path")"
                ;;
        esac
    fi

    [ -n "$NFT_INCLUDE_DIR" ] || NFT_INCLUDE_DIR="/etc/nftables.d"

    NFT_PERSIST_FILE="${NFT_INCLUDE_DIR}/dnat-nft.nft"
}

rebuild_state_file_from_conf() {
    local line
    local local_port
    local right
    local remote_host
    local remote_port
    local remote_ip

    [ -s "${CONF_FILE}" ] || return 0

    : > "${STATE_FILE}"
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        case "$line" in
            *">"*":"*) ;;
            *)
                log_warn "忽略无效配置行: $line"
                continue
                ;;
        esac

        local_port="${line%%>*}"
        right="${line#*>}"
        remote_host="${right%:*}"
        remote_port="${right##*:}"
        remote_ip="$(resolve_host "$remote_host")"

        if [ -z "$remote_ip" ]; then
            log_warn "持久化跳过: 无法解析 ${remote_host}"
            continue
        fi

        printf '%s>%s:%s=%s\n' "$local_port" "$remote_host" "$remote_port" "$remote_ip" >> "${STATE_FILE}"
    done < "${CONF_FILE}"
}

run_nft_with_context() {
    local context="$1"
    shift
    local err

    if err="$(nft "$@" 2>&1)"; then
        return 0
    fi

    log_warn "${context}: ${err}"
    return 1
}

list_managed_forward_rule_handles() {
    local family="$1"
    local table="$2"
    local chain="$3"

    nft -a list chain "$family" "$table" "$chain" 2>/dev/null | awk '
        /comment "(dnat_nft_allow_|dnat_nft_fb_)/ {
            for (i = 1; i <= NF; i++) {
                if ($i == "handle" && (i + 1) <= NF) {
                    print $(i + 1)
                    break
                }
            }
        }
    '
}

delete_managed_forward_rules() {
    local family="$1"
    local table="$2"
    local chain="$3"
    local handles
    local handle

    handles="$(list_managed_forward_rule_handles "$family" "$table" "$chain")"
    [ -z "$handles" ] && return 0

    while IFS= read -r handle; do
        [ -z "$handle" ] && continue
        run_nft_with_context "无法删除旧的 forward 托管规则: ${family}/${table}/${chain}#${handle}" \
            delete rule "$family" "$table" "$chain" handle "$handle" || true
    done <<EOF
$handles
EOF
}

ensure_forward_fallback_rules() {
    local family="$1"
    local table="$2"
    local chain="$3"
    local line
    local left
    local local_port
    local right
    local remote_host
    local remote_port
    local remote_ip
    local c_req_tcp
    local c_req_udp
    local c_rsp_tcp
    local c_rsp_udp

    case "$family" in
        ip|inet) ;;
        *) return 0 ;;
    esac

    [ -s "$STATE_FILE" ] || return 0

    while IFS= read -r line; do
        [ -z "$line" ] && continue
        left="${line%%=*}"
        remote_ip="${line##*=}"
        local_port="${left%%>*}"
        right="${left#*>}"
        remote_host="${right%:*}"
        remote_port="${right##*:}"

        c_req_tcp="dnat_nft_fb_tcp_req_${local_port}_${remote_port}"
        c_req_udp="dnat_nft_fb_udp_req_${local_port}_${remote_port}"
        c_rsp_tcp="dnat_nft_fb_tcp_rsp_${local_port}_${remote_port}"
        c_rsp_udp="dnat_nft_fb_udp_rsp_${local_port}_${remote_port}"

        if ! nft list chain "$family" "$table" "$chain" 2>/dev/null | grep -Fq "$c_req_tcp"; then
            run_nft_with_context "无法插入 forward 放行规则(fallback tcp req): ${family}/${table}/${chain}" \
                insert rule "$family" "$table" "$chain" ip daddr "$remote_ip" tcp dport "$remote_port" accept comment "$c_req_tcp" || true
        fi

        if ! nft list chain "$family" "$table" "$chain" 2>/dev/null | grep -Fq "$c_req_udp"; then
            run_nft_with_context "无法插入 forward 放行规则(fallback udp req): ${family}/${table}/${chain}" \
                insert rule "$family" "$table" "$chain" ip daddr "$remote_ip" udp dport "$remote_port" accept comment "$c_req_udp" || true
        fi

        if ! nft list chain "$family" "$table" "$chain" 2>/dev/null | grep -Fq "$c_rsp_tcp"; then
            run_nft_with_context "无法插入 forward 放行规则(fallback tcp rsp): ${family}/${table}/${chain}" \
                insert rule "$family" "$table" "$chain" ip saddr "$remote_ip" tcp sport "$remote_port" accept comment "$c_rsp_tcp" || true
        fi

        if ! nft list chain "$family" "$table" "$chain" 2>/dev/null | grep -Fq "$c_rsp_udp"; then
            run_nft_with_context "无法插入 forward 放行规则(fallback udp rsp): ${family}/${table}/${chain}" \
                insert rule "$family" "$table" "$chain" ip saddr "$remote_ip" udp sport "$remote_port" accept comment "$c_rsp_udp" || true
        fi
    done < "$STATE_FILE"
}

ensure_forward_accept_rules() {
    local chains
    local line
    local family
    local table
    local chain
    local ct_est_comment="dnat_nft_allow_established"
    local ct_dnat_comment="dnat_nft_allow_dnat"
    local has_chain=0
    local has_state_rules=0
    local need_fallback=0

    chains=""

    if nft list chain inet filter forward >/dev/null 2>&1; then
        chains="inet|filter|forward"
    fi

    line="$(list_forward_base_chains | sort -u)"
    if [ -n "$line" ]; then
        if [ -n "$chains" ]; then
            chains="${chains}\n${line}"
        else
            chains="$line"
        fi
    fi

    chains="$(printf '%b\n' "$chains" | awk 'NF { if (!seen[$0]++) print $0 }')"
    if [ -z "$chains" ]; then
        log_warn "未检测到 forward 基链，未插入 dnat-nft 放行规则"
        return 0
    fi

    if [ -s "$STATE_FILE" ]; then
        has_state_rules=1
    fi

    while IFS='|' read -r family table chain; do
        [ -z "$family" ] && continue
        [ -z "$table" ] && continue
        [ -z "$chain" ] && continue
        has_chain=1

        delete_managed_forward_rules "$family" "$table" "$chain"

        [ "$has_state_rules" -eq 1 ] || continue

        need_fallback=0

        if ! run_nft_with_context "无法插入 forward 放行规则(ct established): ${family}/${table}/${chain}" \
            insert rule "$family" "$table" "$chain" ct state established,related accept comment "$ct_est_comment"; then
            need_fallback=1
        fi

        if ! run_nft_with_context "无法插入 forward 放行规则(ct dnat): ${family}/${table}/${chain}" \
            insert rule "$family" "$table" "$chain" ct status dnat accept comment "$ct_dnat_comment"; then
            need_fallback=1
        fi

        if [ "$need_fallback" -eq 1 ]; then
            ensure_forward_fallback_rules "$family" "$table" "$chain"
        fi
    done <<EOF
$chains
EOF

    [ "$has_chain" -eq 0 ] && log_warn "未检测到可写入的 forward 基链"
}

render_persistent_rules_file() {
    local tmp_file
    local line
    local left
    local local_port
    local right
    local remote_host
    local remote_port
    local remote_ip

    init_nft_persistence_paths

    if [ ! -f "${STATE_FILE}" ]; then
        touch "${STATE_FILE}" || return 1
    fi

    if [ ! -s "${STATE_FILE}" ]; then
        rebuild_state_file_from_conf
    fi

    tmp_file="${NFT_PERSIST_FILE}.tmp"
    mkdir -p "${NFT_INCLUDE_DIR}"

    {
        echo "# Managed by dnat-nft"
        echo "table ip ${TABLE_NAME} {"
        echo "  chain prerouting {"
        echo "    type nat hook prerouting priority dstnat; policy accept;"

        while IFS= read -r line; do
            [ -z "$line" ] && continue
            left="${line%%=*}"
            remote_ip="${line##*=}"
            local_port="${left%%>*}"
            right="${left#*>}"
            remote_host="${right%:*}"
            remote_port="${right##*:}"

            echo "    tcp dport ${local_port} dnat to ${remote_ip}:${remote_port} comment \"DNAT TCP ${local_port}->${remote_host}:${remote_port}\""
            echo "    udp dport ${local_port} dnat to ${remote_ip}:${remote_port} comment \"DNAT UDP ${local_port}->${remote_host}:${remote_port}\""
        done < "${STATE_FILE}"

        echo "  }"
        echo "  chain output {"
        echo "    type nat hook output priority dstnat; policy accept;"

        while IFS= read -r line; do
            [ -z "$line" ] && continue
            left="${line%%=*}"
            remote_ip="${line##*=}"
            local_port="${left%%>*}"
            right="${left#*>}"
            remote_host="${right%:*}"
            remote_port="${right##*:}"

            echo "    fib daddr type local tcp dport ${local_port} dnat to ${remote_ip}:${remote_port} comment \"DNAT OUTPUT TCP ${local_port}->${remote_host}:${remote_port}\""
            echo "    fib daddr type local udp dport ${local_port} dnat to ${remote_ip}:${remote_port} comment \"DNAT OUTPUT UDP ${local_port}->${remote_host}:${remote_port}\""
        done < "${STATE_FILE}"

        echo "  }"
        echo "  chain postrouting {"
        echo "    type nat hook postrouting priority srcnat; policy accept;"

        while IFS= read -r line; do
            [ -z "$line" ] && continue
            left="${line%%=*}"
            remote_ip="${line##*=}"
            right="${left#*>}"
            remote_host="${right%:*}"
            remote_port="${right##*:}"

            echo "    ip daddr ${remote_ip} tcp dport ${remote_port} masquerade comment \"MASQ TCP ${remote_host}:${remote_port}\""
            echo "    ip daddr ${remote_ip} udp dport ${remote_port} masquerade comment \"MASQ UDP ${remote_host}:${remote_port}\""
        done < "${STATE_FILE}"

        echo "  }"
        echo "}"
    } > "$tmp_file"

    mv "$tmp_file" "${NFT_PERSIST_FILE}"
}

ensure_nft_main_include() {
    init_nft_persistence_paths

    if [ ! -f "${NFT_MAIN_CONF}" ]; then
        cat > "${NFT_MAIN_CONF}" <<EOF
flush ruleset

include "/var/lib/nftables/*.nft"
include "${NFT_INCLUDE_DIR}/*.nft"
EOF
        return 0
    fi

    local escaped_dir
    escaped_dir="$(printf '%s' "$NFT_INCLUDE_DIR" | sed 's/[.[\*^$/]/\\&/g')"

    if grep -Eq "^[[:space:]]*include[[:space:]]+\"${escaped_dir}/(\\*\\.nft|dnat-nft\\.nft)\"" "${NFT_MAIN_CONF}" 2>/dev/null; then
        return 0
    fi

    printf '\ninclude "%s/*.nft"\n' "${NFT_INCLUDE_DIR}" >> "${NFT_MAIN_CONF}"
}

enable_nftables_boot_load() {
    init_service_manager

    if [ "$SERVICE_MANAGER" = "systemd" ]; then
        if systemctl list-unit-files 2>/dev/null | grep -q '^nftables\.service'; then
            SERVICE_ENABLE nftables || true
        fi
    elif [ "$SERVICE_MANAGER" = "openrc" ]; then
        if [ -x /etc/init.d/nftables ]; then
            SERVICE_ENABLE nftables || true
        fi
    fi
}

persist_nft_config() {
    init_nft_persistence_paths

    if [ -z "$NFT_PERSIST_FILE" ]; then
        log_warn "无法确定 nft 持久化文件路径"
        return 0
    fi

    if ! render_persistent_rules_file; then
        log_warn "写入 nft 持久化配置失败: ${NFT_PERSIST_FILE}"
        return 0
    fi

    if ! ensure_nft_main_include; then
        log_warn "更新 nft 主配置失败: ${NFT_MAIN_CONF}"
        return 0
    fi

    if [ ! -f "${NFT_PERSIST_FILE}" ]; then
        log_warn "nft 持久化文件未生成: ${NFT_PERSIST_FILE}"
        return 0
    fi

    enable_nftables_boot_load
    log_info "nft 持久化配置已写入: ${NFT_PERSIST_FILE}"
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
    ensure_forward_accept_rules
    persist_nft_config
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

    if ! run_once; then
        log_error "转发规则应用失败"
        return 1
    fi

    if ! setup_service; then
        log_warn "服务持久化配置失败，但当前规则可能已生效"
    fi

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

    sed "/^${local_port}>/d" "${CONF_FILE}" > "${CONF_FILE}.tmp"
    mv "${CONF_FILE}.tmp" "${CONF_FILE}"

    if ! run_once; then
        log_error "删除规则后重载失败"
        return 1
    fi

    if ! setup_service; then
        log_warn "服务持久化配置失败，但当前规则可能已生效"
    fi

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

    init_nft_persistence_paths

    if has_cmd nft && nft list table ip "${TABLE_NAME}" >/dev/null 2>&1; then
        nft delete table ip "${TABLE_NAME}" >/dev/null 2>&1 || true
    fi

    rm -f "${NFT_PERSIST_FILE}"

    if [ -f "${NFT_MAIN_CONF}" ] && [ -n "${NFT_INCLUDE_DIR}" ]; then
        local escaped_dir
        escaped_dir="$(printf '%s' "$NFT_INCLUDE_DIR" | sed 's/[.[\*^$/]/\\&/g')"
        if grep -Eq "^[[:space:]]*include[[:space:]]+\"${escaped_dir}/" "${NFT_MAIN_CONF}" 2>/dev/null; then
            grep -Ev "^[[:space:]]*include[[:space:]]+\"${escaped_dir}/(\\*\\.nft|dnat-nft\\.nft)\"" "${NFT_MAIN_CONF}" > "${NFT_MAIN_CONF}.tmp" && mv "${NFT_MAIN_CONF}.tmp" "${NFT_MAIN_CONF}"
        fi
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
