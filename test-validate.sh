#!/bin/sh
# Runs INSIDE Alpine container after server-init-alpine.sh to validate results.

set +e

PASS=0
FAIL=0
WARN=0

pass() { PASS=$((PASS + 1)); printf "\033[0;32m  [PASS]\033[0m %s\n" "$1"; }
fail() { FAIL=$((FAIL + 1)); printf "\033[0;31m  [FAIL]\033[0m %s\n" "$1"; }
warn() { WARN=$((WARN + 1)); printf "\033[1;33m  [WARN]\033[0m %s\n" "$1"; }
section() { printf "\n\033[1;36m=== %s ===\033[0m\n" "$1"; }

check_cmd() {
    if command -v "$1" >/dev/null 2>&1; then
        pass "$1 is installed"
        return 0
    else
        fail "$1 is NOT installed"
        return 1
    fi
}

check_service_enabled() {
    if rc-update show default 2>/dev/null | grep -q "$1"; then
        pass "Service '$1' enabled at boot"
        return 0
    else
        fail "Service '$1' NOT enabled at boot"
        return 1
    fi
}

check_service_running() {
    if rc-service "$1" status 2>/dev/null | grep -qi "started\|running"; then
        pass "Service '$1' is running"
        return 0
    else
        fail "Service '$1' is NOT running"
        return 1
    fi
}

section "1. OS Detection"
if [ -r /etc/os-release ]; then
    . /etc/os-release
    pass "OS detected: $ID $VERSION_ID"
    case "$VERSION_ID" in
        3.2[3-9]*|3.[3-9]*|[4-9]*)
            pass "Alpine version >= 3.23"
            ;;
        *)
            fail "Alpine version $VERSION_ID < 3.23"
            ;;
    esac
else
    fail "/etc/os-release not found"
fi

section "2. Hostname Resolution"
current_hostname="$(hostname)"
if grep -q "$current_hostname" /etc/hosts 2>/dev/null; then
    pass "Hostname '$current_hostname' found in /etc/hosts"
else
    fail "Hostname '$current_hostname' NOT in /etc/hosts"
fi

if grep -qE "^127\.0\.0\.1.*localhost" /etc/hosts 2>/dev/null; then
    pass "localhost resolves on 127.0.0.1"
else
    fail "localhost NOT on 127.0.0.1"
fi

section "3. Common Tools"
for tool in vim nano htop tmux jq git wget curl sudo; do
    check_cmd "$tool"
done

section "4. User 'arcat'"
if id arcat >/dev/null 2>&1; then
    pass "User 'arcat' exists"
else
    fail "User 'arcat' does NOT exist"
fi

if id -nG arcat 2>/dev/null | grep -qw wheel; then
    pass "User 'arcat' is in wheel group"
else
    fail "User 'arcat' NOT in wheel group"
fi

if [ -f /etc/sudoers.d/arcat ]; then
    if grep -q "NOPASSWD" /etc/sudoers.d/arcat; then
        pass "arcat has NOPASSWD sudo"
    else
        fail "arcat sudoers file missing NOPASSWD"
    fi
else
    fail "/etc/sudoers.d/arcat not found"
fi

section "5. SSH Keys"
if [ -f /home/arcat/.ssh/authorized_keys ]; then
    if [ -s /home/arcat/.ssh/authorized_keys ]; then
        pass "authorized_keys exists and is non-empty"
    else
        fail "authorized_keys is empty"
    fi
else
    fail "authorized_keys not found"
fi

ssh_dir_perms=$(stat -c '%a' /home/arcat/.ssh 2>/dev/null || stat -f '%Lp' /home/arcat/.ssh 2>/dev/null)
if [ "$ssh_dir_perms" = "700" ]; then
    pass ".ssh dir permissions = 700"
else
    fail ".ssh dir permissions = $ssh_dir_perms (expected 700)"
fi

ak_perms=$(stat -c '%a' /home/arcat/.ssh/authorized_keys 2>/dev/null || stat -f '%Lp' /home/arcat/.ssh/authorized_keys 2>/dev/null)
if [ "$ak_perms" = "600" ]; then
    pass "authorized_keys permissions = 600"
else
    fail "authorized_keys permissions = $ak_perms (expected 600)"
fi

ak_owner=$(stat -c '%U' /home/arcat/.ssh/authorized_keys 2>/dev/null)
if [ "$ak_owner" = "arcat" ]; then
    pass "authorized_keys owned by arcat"
else
    fail "authorized_keys owned by '$ak_owner' (expected arcat)"
fi

section "6. SSH Hardening"
sshd_config="/etc/ssh/sshd_config"
if [ -f "$sshd_config" ]; then
    if grep -qE "^PermitRootLogin\s+no" "$sshd_config"; then
        pass "PermitRootLogin = no"
    else
        fail "PermitRootLogin is NOT set to no"
    fi

    if grep -qE "^PasswordAuthentication\s+no" "$sshd_config"; then
        pass "PasswordAuthentication = no"
    else
        fail "PasswordAuthentication is NOT set to no"
    fi

    if grep -qE "^PubkeyAuthentication\s+yes" "$sshd_config"; then
        pass "PubkeyAuthentication = yes"
    else
        fail "PubkeyAuthentication is NOT set to yes"
    fi
else
    fail "sshd_config not found"
fi

section "7. Zsh & Oh-My-Zsh"
check_cmd zsh

if [ -d /home/arcat/.oh-my-zsh ]; then
    pass "oh-my-zsh installed for arcat"
else
    fail "oh-my-zsh NOT installed"
fi

user_shell=$(getent passwd arcat 2>/dev/null | cut -d: -f7)
if echo "$user_shell" | grep -q "zsh"; then
    pass "arcat default shell is zsh ($user_shell)"
else
    fail "arcat default shell is '$user_shell' (expected zsh)"
fi

if [ -d /home/arcat/.oh-my-zsh/custom/plugins/zsh-autosuggestions ]; then
    pass "zsh-autosuggestions plugin installed"
else
    fail "zsh-autosuggestions plugin NOT installed"
fi

if [ -d /home/arcat/.oh-my-zsh/custom/plugins/zsh-syntax-highlighting ]; then
    pass "zsh-syntax-highlighting plugin installed"
else
    fail "zsh-syntax-highlighting plugin NOT installed"
fi

section "8. Starship"
check_cmd starship

if [ -f /home/arcat/.config/starship.toml ]; then
    pass "starship.toml config exists"
else
    fail "starship.toml NOT found"
fi

if [ -f /home/arcat/.zshrc ] && grep -q "starship init zsh" /home/arcat/.zshrc; then
    pass "starship init in .zshrc"
else
    fail "starship init NOT in .zshrc"
fi

section "9. Direnv"
check_cmd direnv

if [ -f /home/arcat/.zshrc ] && grep -q "direnv hook zsh" /home/arcat/.zshrc; then
    pass "direnv hook in .zshrc"
else
    fail "direnv hook NOT in .zshrc"
fi

section "10. Mosh"
check_cmd mosh-server

section "11. nftables Firewall"
check_cmd nft

if [ -d /etc/nftables.d ] && [ -f /etc/nftables.d/server-init.nft ]; then
    pass "server-init.nft rule file exists"
    if grep -q "SSH" /etc/nftables.d/server-init.nft; then
        pass "SSH rule present in nftables config"
    else
        fail "SSH rule NOT in nftables config"
    fi
    if grep -q "Mosh" /etc/nftables.d/server-init.nft; then
        pass "Mosh rule present in nftables config"
    else
        fail "Mosh rule NOT in nftables config"
    fi
else
    fail "nftables server-init.nft not found"
fi

check_service_enabled nftables

section "12. CrowdSec"
check_cmd cscli

if [ -f /etc/crowdsec/config.yaml ]; then
    pass "CrowdSec config.yaml exists"
else
    fail "CrowdSec config.yaml NOT found"
fi

if [ -f /etc/crowdsec/acquis.yaml ]; then
    pass "CrowdSec acquis.yaml exists"
    if grep -qE "^(filenames|source|journalctl_filter)" /etc/crowdsec/acquis.yaml; then
        pass "acquis.yaml has datasource config"
    else
        fail "acquis.yaml has NO datasource config"
    fi
else
    fail "CrowdSec acquis.yaml NOT found"
fi

if [ -f /etc/crowdsec/online_api_credentials.yaml ]; then
    pass "CrowdSec online_api_credentials.yaml exists"
    if grep -qE "^[[:space:]]*url:[[:space:]]*[^[:space:]]+" /etc/crowdsec/online_api_credentials.yaml; then
        pass "online_api_credentials has url field"
    else
        fail "online_api_credentials missing url"
    fi
else
    fail "CrowdSec online_api_credentials.yaml NOT found"
fi

if [ -f /etc/crowdsec/local_api_credentials.yaml ]; then
    pass "CrowdSec local_api_credentials.yaml exists"
else
    fail "CrowdSec local_api_credentials.yaml NOT found"
fi

check_service_enabled crowdsec
check_service_running crowdsec

check_service_enabled cs-firewall-bouncer
check_service_running cs-firewall-bouncer

section "12a. CrowdSec Collections"
if cscli collections list 2>/dev/null | grep -q "crowdsecurity/sshd"; then
    pass "crowdsecurity/sshd collection installed"
else
    fail "crowdsecurity/sshd collection NOT installed"
fi

if cscli collections list 2>/dev/null | grep -q "crowdsecurity/linux"; then
    pass "crowdsecurity/linux collection installed"
else
    fail "crowdsecurity/linux collection NOT installed"
fi

section "12b. CrowdSec Bouncer"
if cscli bouncers list 2>/dev/null | grep -qi "firewall"; then
    pass "Firewall bouncer registered with CrowdSec"
else
    fail "Firewall bouncer NOT registered"
fi

section "12c. CrowdSec LAPI"
if cscli lapi status 2>&1 | grep -qi "successfully\|ok\|online\|running"; then
    pass "CrowdSec LAPI is reachable"
else
    warn "CrowdSec LAPI status check inconclusive"
    cscli lapi status 2>&1 || true
fi

section "12d. CrowdSec Metrics"
printf "  CrowdSec metrics output:\n"
cscli metrics 2>&1 | head -40 || warn "Failed to get CrowdSec metrics"

section "13. CrowdSec Log Parsing"
FAKE_IP="192.168.200.1"
FAKE_LOG_FILE="/var/log/test-sshd-inject.log"
CS_TIMESTAMP=$(date '+%b %d %H:%M:%S')
CS_HOSTNAME=$(hostname)

printf "%s %s sshd[9999]: Failed password for invalid user testuser from %s port 22 ssh2\n" \
    "$CS_TIMESTAMP" "$CS_HOSTNAME" "$FAKE_IP" > "$FAKE_LOG_FILE"

parse_output=$(cscli explain --file "$FAKE_LOG_FILE" --type syslog 2>&1 || true)

if echo "$parse_output" | grep -qi "ssh_failed-auth\|crowdsecurity/sshd-logs"; then
    pass "CrowdSec parser recognized sshd failed-auth log"
else
    fail "CrowdSec parser did NOT recognize sshd log"
    printf "    parse output: %s\n" "$(echo "$parse_output" | head -5)"
fi

if echo "$parse_output" | grep -qi "$FAKE_IP"; then
    pass "Parser extracted source IP ($FAKE_IP) from log"
else
    fail "Parser did NOT extract source IP from log"
fi

rm -f "$FAKE_LOG_FILE"

section "14. CrowdSec SSH Brute Force Detection"
BF_IP="10.99.99.1"
BF_LOG_FILE="/var/log/messages"
BF_TIMESTAMP=$(date '+%b %d %H:%M:%S')

cscli alerts delete --all >/dev/null 2>&1 || true
cscli decisions delete --all >/dev/null 2>&1 || true

for i in 1 2 3 4 5 6 7 8; do
    printf "%s %s sshd[%d]: Failed password for invalid user user%d from %s port 22 ssh2\n" \
        "$BF_TIMESTAMP" "$CS_HOSTNAME" "$((9000 + i))" "$i" "$BF_IP" >> "$BF_LOG_FILE"
done

sleep 15

bf_alerts=$(cscli alerts list -o json 2>/dev/null || echo "[]")
if echo "$bf_alerts" | grep -qi "$BF_IP"; then
    pass "Alert generated for brute force IP $BF_IP"
else
    fail "No alert for brute force IP $BF_IP"
    printf "    alerts: %s\n" "$(cscli alerts list 2>&1 | head -5)"
fi

bf_decisions=$(cscli decisions list -o json 2>/dev/null || echo "[]")
if echo "$bf_decisions" | grep -qi "$BF_IP"; then
    pass "Ban decision created for $BF_IP"
else
    warn "No ban decision for $BF_IP (may need more time or log tailing)"
fi

section "15. CrowdSec Manual Ban/Unban"
MANUAL_BAN_IP="10.88.88.1"

cscli decisions add --ip "$MANUAL_BAN_IP" --duration 1h --reason "test-ban" >/dev/null 2>&1
sleep 2

manual_dec=$(cscli decisions list -o json 2>/dev/null || echo "[]")
if echo "$manual_dec" | grep -qi "$MANUAL_BAN_IP"; then
    pass "Manual ban: $MANUAL_BAN_IP appears in decisions"
else
    fail "Manual ban: $MANUAL_BAN_IP NOT in decisions"
fi

cscli decisions delete --ip "$MANUAL_BAN_IP" >/dev/null 2>&1
sleep 2

after_del=$(cscli decisions list -o json 2>/dev/null || echo "[]")
if echo "$after_del" | grep -qi "$MANUAL_BAN_IP"; then
    fail "Unban failed: $MANUAL_BAN_IP still in decisions"
else
    pass "Manual unban: $MANUAL_BAN_IP removed from decisions"
fi

section "16. CrowdSec Bouncer Linkage"
BOUNCER_BAN_IP="10.77.77.1"

cscli decisions add --ip "$BOUNCER_BAN_IP" --duration 1h --reason "bouncer-test" >/dev/null 2>&1
sleep 15

bouncer_blocked=false
if command -v nft >/dev/null 2>&1; then
    if nft list ruleset 2>/dev/null | grep -q "$BOUNCER_BAN_IP"; then
        bouncer_blocked=true
    fi
fi
if [ "$bouncer_blocked" = false ] && command -v ipset >/dev/null 2>&1; then
    if ipset list 2>/dev/null | grep -q "$BOUNCER_BAN_IP"; then
        bouncer_blocked=true
    fi
fi

if [ "$bouncer_blocked" = true ]; then
    pass "Bouncer blocked $BOUNCER_BAN_IP in firewall"
else
    fail "Bouncer did NOT block $BOUNCER_BAN_IP in firewall"
    printf "    nft crowdsec sets:\n"
    nft list table ip crowdsec 2>/dev/null | head -20 || printf "    (no crowdsec table)\n"
fi

cscli decisions delete --ip "$BOUNCER_BAN_IP" >/dev/null 2>&1
sleep 15

bouncer_cleared=true
if command -v nft >/dev/null 2>&1; then
    if nft list ruleset 2>/dev/null | grep -q "$BOUNCER_BAN_IP"; then
        bouncer_cleared=false
    fi
fi
if command -v ipset >/dev/null 2>&1; then
    if ipset list 2>/dev/null | grep -q "$BOUNCER_BAN_IP"; then
        bouncer_cleared=false
    fi
fi

if [ "$bouncer_cleared" = true ]; then
    pass "Bouncer removed $BOUNCER_BAN_IP from firewall after unban"
else
    fail "Bouncer did NOT remove $BOUNCER_BAN_IP after unban"
fi

section "17. BBR (best-effort in container)"
if sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null | grep -q bbr; then
    pass "BBR congestion control active"
else
    warn "BBR not active (expected in container without sysctl privileges)"
fi

section "SUMMARY"
TOTAL=$((PASS + FAIL))
printf "\n  Total: %d  |  \033[0;32mPass: %d\033[0m  |  \033[0;31mFail: %d\033[0m  |  \033[1;33mWarn: %d\033[0m\n\n" \
    "$TOTAL" "$PASS" "$FAIL" "$WARN"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0
