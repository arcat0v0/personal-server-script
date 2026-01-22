#!/bin/bash

#############################################
# Server Initialization Script
# Supports: Debian, Ubuntu
# Features:
# - Fix hostname resolution
# - Disable root login
# - Create sudo user 'arcat'
# - Import SSH keys from GitHub
# - Create additional users with their SSH keys (optional)
# - Configure sudo privileges for additional users
# - Update system
# - Install and configure zsh with oh-my-zsh
# - Install and configure starship prompt
# - Install and configure direnv
# - Install mosh for better remote connections
# - Configure UFW firewall (nftables backend)
# - Install and configure CrowdSec for intrusion prevention
# - Enable BBR if supported
# - CN mode: install dae after base tools and skip optional installers
#############################################

set -e

# Global variables
ADDITIONAL_USERS=""
ADD_ADDITIONAL_USERS=false
FIREWALL="ufw" # supported: ufw, nftables
DAE_SUBSCRIPTION_URL=""
DAE_CONFIG_TEMPLATE_URL="https://raw.githubusercontent.com/arcat0v0/personal-server-script/main/config-template.dae"

# CN network handling (override via env if needed).
# CN_HTTP_PROXY example: http://127.0.0.1:7890
CN_HTTP_PROXY="${CN_HTTP_PROXY:-}"
# Default URL prefix proxy for CN (useful for GitHub/raw assets).
CN_PROXY_PREFIX="${CN_PROXY_PREFIX:-https://ghfast.top/}"
# Gitee mirror base for GitHub repos when CN.
CN_GIT_MIRROR_BASE="${CN_GIT_MIRROR_BASE:-https://gitee.com/mirrors}"

IS_CN_MACHINE=""
FORCE_CN="${FORCE_CN:-}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Log functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Command helpers
has_cmd() {
    command -v "$1" >/dev/null 2>&1
}

# Detect whether the machine is in China (best-effort).
is_cn_machine() {
    if [ -n "$IS_CN_MACHINE" ]; then
        [ "$IS_CN_MACHINE" = "true" ]
        return
    fi

    if [ "${FORCE_CN:-}" = "1" ]; then
        IS_CN_MACHINE="true"
        return
    fi

    if [ "${FORCE_CN:-}" = "0" ]; then
        IS_CN_MACHINE="false"
        return
    fi

    local country_code=""
    if has_cmd curl; then
        country_code=$(curl -fsSL --connect-timeout 3 --max-time 5 https://ipinfo.io/country 2>/dev/null | tr -d '\r\n' || true)
        if [ -z "$country_code" ]; then
            country_code=$(curl -fsSL --connect-timeout 3 --max-time 5 https://ipapi.co/country/ 2>/dev/null | tr -d '\r\n' || true)
        fi
    fi

    if [ "$country_code" = "CN" ]; then
        IS_CN_MACHINE="true"
    else
        IS_CN_MACHINE="false"
    fi

    if [ "$IS_CN_MACHINE" = "true" ]; then
        return 0
    fi
    return 1
}

proxy_url() {
    local url="$1"
    if is_cn_machine && [ -n "$CN_PROXY_PREFIX" ]; then
        case "$url" in
            "${CN_PROXY_PREFIX}"*) echo "$url" ;;
            https://github.com/*|https://raw.githubusercontent.com/*|https://gist.githubusercontent.com/*)
                echo "${CN_PROXY_PREFIX}${url}"
                ;;
            *)
                echo "$url"
                ;;
        esac
        return
    fi
    echo "$url"
}

curl_fetch() {
    local url="$1"
    local output="${2:-}"
    local final_url
    local curl_args=(-fsSL --connect-timeout 10 --max-time 30)

    if is_cn_machine && [ -n "$CN_HTTP_PROXY" ]; then
        curl_args+=(--proxy "$CN_HTTP_PROXY")
        final_url="$url"
    else
        final_url="$(proxy_url "$url")"
    fi

    if [ -n "$output" ]; then
        curl "${curl_args[@]}" "$final_url" -o "$output"
    else
        curl "${curl_args[@]}" "$final_url"
    fi
}

apply_cn_proxy_env() {
    if is_cn_machine; then
        if [ -n "$CN_HTTP_PROXY" ]; then
            export http_proxy="$CN_HTTP_PROXY"
            export https_proxy="$CN_HTTP_PROXY"
            log_info "CN proxy enabled via CN_HTTP_PROXY"
        else
            log_warn "CN machine detected; set CN_HTTP_PROXY for non-curl tools if needed"
        fi
    fi
}

report_cn_optimization() {
    if is_cn_machine; then
        if [ "${FORCE_CN:-}" = "1" ]; then
            log_info "China optimized address: enabled (forced)"
        else
            log_info "China optimized address: enabled (CN network detected)"
        fi
    else
        if [ "${FORCE_CN:-}" = "0" ]; then
            log_info "China optimized address: disabled (forced)"
        else
            log_info "China optimized address: disabled"
        fi
    fi
}

prompt_dae_subscription() {
    if [ -n "$DAE_SUBSCRIPTION_URL" ]; then
        return
    fi

    echo ""
    log_info "CN mode detected: dae will be installed and configured"
    read -p "$(printf "%b" "${YELLOW}[PROMPT]${NC} Enter dae subscription URL (my_sub): ")" -r < /dev/tty || return 1
    if [ -z "$REPLY" ]; then
        log_error "Subscription URL is required for dae configuration"
        return 1
    fi
    DAE_SUBSCRIPTION_URL="$REPLY"
}

install_dae() {
    log_info "Installing dae..."
    sudo sh -c "$(wget -qO- https://cdn.jsdelivr.net/gh/daeuniverse/dae-installer/installer.sh)" @ install use-cdn
    log_info "dae installed"
}

configure_dae() {
    local config_src="/tmp/dae-config-template.dae"
    local config_dir="/usr/local/etc/dae"
    local config_path="${config_dir}/config.dae"
    local escaped_sub=""
    local template_url=""

    template_url="$(proxy_url "$DAE_CONFIG_TEMPLATE_URL")"
    if ! curl -fsSL "$template_url" -o "$config_src"; then
        log_error "Failed to download dae config template from $template_url"
        return 1
    fi

    escaped_sub="${DAE_SUBSCRIPTION_URL//\\/\\\\}"
    escaped_sub="${escaped_sub//&/\\&}"
    escaped_sub="${escaped_sub//#/\\#}"

    mkdir -p "$config_dir"
    cp "$config_src" "$config_path"
    sed -i "s#^\\(\\s*my_sub:\\s*\\).*\$#\\1'${escaped_sub}'#" "$config_path"
    log_info "dae config written to $config_path"
}

# Detect OS and set package/service helpers.
detect_os() {
    if [ "$(id -u)" -ne 0 ]; then
        log_error "This script must be run as root."
        exit 1
    fi

    if [ -r /etc/os-release ]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        OS_ID="${ID:-unknown}"
        OS_VERSION="${VERSION_ID:-unknown}"
    else
        OS_ID="unknown"
        OS_VERSION="unknown"
    fi

    case "$OS_ID" in
        debian|ubuntu)
            log_info "Detected OS: $OS_ID $OS_VERSION"
            ;;
        *)
            log_warn "Unsupported OS: $OS_ID $OS_VERSION. Will try to continue best-effort."
            ;;
    esac

    if has_cmd apt-get; then
        PKG_UPDATE="apt-get update -y"
        PKG_INSTALL="apt-get install -y"
    elif has_cmd apt; then
        PKG_UPDATE="apt update -y"
        PKG_INSTALL="apt install -y"
    else
        log_error "No supported package manager found (apt-get/apt)."
        exit 1
    fi

    # Bootstrap essential tools used early in the script.
    if ! has_cmd curl; then
        log_info "curl not found, installing..."
        $PKG_UPDATE
        $PKG_INSTALL curl ca-certificates
    fi

    if has_cmd systemctl; then
        SERVICE_RESTART() { systemctl restart "$1"; }
        SERVICE_START() { systemctl start "$1"; }
        SERVICE_ENABLE() { systemctl enable "$1"; }
        SERVICE_RELOAD() { systemctl reload "$1"; }
    elif has_cmd service; then
        SERVICE_RESTART() { service "$1" restart; }
        SERVICE_START() { service "$1" start; }
        SERVICE_ENABLE() {
            if has_cmd update-rc.d; then
                update-rc.d "$1" defaults >/dev/null 2>&1 || true
            else
                log_warn "Cannot enable service $1 (systemctl/update-rc.d not found)."
            fi
        }
        SERVICE_RELOAD() { service "$1" reload || service "$1" restart; }
    else
        log_warn "No service manager found (systemctl/service). Service operations may fail."
        SERVICE_RESTART() { log_warn "Skipping restart for $1"; }
        SERVICE_START() { log_warn "Skipping start for $1"; }
        SERVICE_ENABLE() { log_warn "Skipping enable for $1"; }
        SERVICE_RELOAD() { log_warn "Skipping reload for $1"; }
    fi
}

# Parse command line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -a|--add-users)
                ADD_ADDITIONAL_USERS=true
                shift
                ;;
            -u|--users)
                ADDITIONAL_USERS="$2"
                ADD_ADDITIONAL_USERS=true
                shift 2
                ;;
            --dae-sub)
                DAE_SUBSCRIPTION_URL="$2"
                shift 2
                ;;
            --cn)
                FORCE_CN="1"
                shift
                ;;
            --firewall)
                FIREWALL="${2:-}"
                if [ "$FIREWALL" != "nftables" ] && [ "$FIREWALL" != "ufw" ]; then
                    log_error "Invalid firewall: $FIREWALL (expected: nftables or ufw)"
                    exit 1
                fi
                shift 2
                ;;
            -h|--help)
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  -a, --add-users         Enable adding additional users (will prompt for details)"
                echo "  -u, --users USERS       Specify additional users (semicolon-separated)"
                echo "      --dae-sub URL       Set dae subscription URL (my_sub)"
                echo "      --cn                Force China optimized addresses"
                echo "      --firewall FW       Firewall implementation (default: nftables)"
                echo "                          FW: nftables | ufw"
                echo "                          Format: username@key_url[:sudo|:nopasswd]"
                echo "                          :sudo     - Sudo access (password required)"
                echo "                          :nopasswd - Sudo access (passwordless)"
                echo "  -h, --help              Show this help message"
                echo ""
                echo "Examples:"
                echo "  $0                                    # Run with interactive prompts"
                echo "  $0 -a                                 # Enable additional users, will prompt for details"
                echo "  $0 -u 'alice@url:nopasswd;bob@url:sudo;charlie@url'"
                echo "  $0 --cn --dae-sub URL                 # CN mode with dae subscription URL"
                echo "  $0 --cn                               # Force China optimized addresses"
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                echo "Use -h or --help for usage information"
                exit 1
                ;;
        esac
    done
}

# Interactive prompt for additional users
prompt_additional_users() {
    if [ "$ADD_ADDITIONAL_USERS" = false ]; then
        echo ""
        read -p "$(echo -e ${YELLOW}[PROMPT]${NC} Do you want to create additional users? \(y/N\): )" -n 1 -r < /dev/tty || return 0
        echo ""
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            ADD_ADDITIONAL_USERS=true
        else
            return 0
        fi
    fi

    if [ "$ADD_ADDITIONAL_USERS" = true ] && [ -z "$ADDITIONAL_USERS" ]; then
        echo ""
        log_info "You can add multiple users. For each user, provide:"
        log_info "  - Username"
        log_info "  - SSH key URL (e.g., https://github.com/username.keys)"
        log_info "  - Privileges (None, Sudo, or NOPASSWD)"
        echo ""

        local user_entries=""
        local continue_adding=true

        while [ "$continue_adding" = true ]; do
            echo -e "${YELLOW}[PROMPT]${NC} Enter username:"
            read -r username < /dev/tty || break

            if [ -z "$username" ]; then
                log_warn "Username cannot be empty"
                continue
            fi

            echo -e "${YELLOW}[PROMPT]${NC} Enter SSH key URL for $username:"
            read -r key_url < /dev/tty || break

            if [ -z "$key_url" ]; then
                log_warn "Key URL cannot be empty"
                continue
            fi

            # Use printf with proper quoting to avoid bare parentheses causing bash parse errors.
            read -p "$(printf "%b" "${YELLOW}[PROMPT]${NC} Should $username have sudo privileges? (y/N): ")" -n 1 -r < /dev/tty || local sudo_choice=""
            echo ""
            
            local priv_suffix=""
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                read -p "$(printf "%b" "${YELLOW}[PROMPT]${NC} Enable passwordless sudo (NOPASSWD) for $username? (y/N): ")" -n 1 -r < /dev/tty || local nopasswd_choice=""
                echo ""
                if [[ $REPLY =~ ^[Yy]$ ]]; then
                    priv_suffix=":nopasswd"
                else
                    priv_suffix=":sudo"
                fi
            fi

            # Add to user entries (format: username@key_url[:sudo|:nopasswd])
            if [ -z "$user_entries" ]; then
                user_entries="${username}@${key_url}${priv_suffix}"
            else
                user_entries="${user_entries};${username}@${key_url}${priv_suffix}"
            fi

            log_info "Added user: $username${priv_suffix}"

            echo ""
            read -p "$(echo -e ${YELLOW}[PROMPT]${NC} Add another user? \(y/N\): )" -n 1 -r < /dev/tty || break
            echo ""
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                continue_adding=false
            fi
        done

        ADDITIONAL_USERS="$user_entries"

        if [ -z "$ADDITIONAL_USERS" ]; then
            log_warn "No users provided, skipping additional users"
            ADD_ADDITIONAL_USERS=false
        fi
    fi
}

# Fix hostname resolution issues (avoid sudo warnings).
fix_hostname() {
    log_info "Fixing hostname resolution..."

    local hostname
    hostname="$(hostname)"

    if [ -z "$hostname" ]; then
        log_warn "Unable to determine hostname, skipping"
        return
    fi

    local hosts_file="/etc/hosts"
    cp "$hosts_file" "${hosts_file}.backup.$(date +%Y%m%d_%H%M%S)"

    # Ensure 127.0.1.1 maps to hostname on Debian/Ubuntu.
    if grep -qE "^127\\.0\\.1\\.1\\s+" "$hosts_file"; then
        if ! grep -qE "^127\\.0\\.1\\.1\\s+.*\\b${hostname}\\b" "$hosts_file"; then
            sed -i "s/^127\\.0\\.1\\.1\\s\\+.*/127.0.1.1\t${hostname}/" "$hosts_file"
        fi
    else
        echo -e "127.0.1.1\t${hostname}" >> "$hosts_file"
    fi

    log_info "Hostname resolution fixed for: $hostname"
}

# Install common base tools (vim, etc.).
install_common_tools() {
    log_info "Installing common tools..."

    local pkgs=(
        vim
        nano
        less
        htop
        tmux
        unzip
        zip
        rsync
        lsof
        net-tools
        jq
        wget
        git
        ca-certificates
        gnupg
        sudo
    )

    $PKG_INSTALL "${pkgs[@]}"
    log_info "Common tools installed"
}

# Update system packages.
update_system() {
    log_info "Updating system packages..."

    $PKG_UPDATE

    if has_cmd apt-get; then
        DEBIAN_FRONTEND=noninteractive apt-get upgrade -y
        DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y
        apt-get autoremove -y
        apt-get autoclean -y
    else
        DEBIAN_FRONTEND=noninteractive apt upgrade -y
        DEBIAN_FRONTEND=noninteractive apt full-upgrade -y
        apt autoremove -y
        apt autoclean -y
    fi

    install_common_tools
    log_info "System update completed"
}

# Create main sudo user.
create_user() {
    local username="arcat"

    log_info "Creating main user: $username"

    if id "$username" &>/dev/null; then
        log_warn "User $username already exists, skipping creation"
    else
        useradd -m -s /bin/bash "$username"
        log_info "User $username created"
    fi

    usermod -aG sudo "$username"

    # Configure passwordless sudo
    echo "$username ALL=(ALL) NOPASSWD:ALL" > "/etc/sudoers.d/$username"
    chmod 0440 "/etc/sudoers.d/$username"

    log_info "User $username granted sudo privileges (NOPASSWD)"
}

# Import SSH keys for main user from GitHub (with CF mirror fallback).
import_ssh_keys() {
    local username="arcat"
    local github_user="arcat0v0"
    local primary_url="https://github.com/${github_user}.keys"
    local cf_worker_url="https://arcat-keys.xvx.rs"
    local mirror_url="${cf_worker_url}/${github_user}.keys"

    log_info "Importing SSH keys for $username..."

    local ssh_dir="/home/$username/.ssh"
    mkdir -p "$ssh_dir"

    if curl_fetch "$primary_url" "$ssh_dir/authorized_keys"; then
        log_info "Downloaded SSH keys from GitHub"
    elif curl_fetch "$mirror_url" "$ssh_dir/authorized_keys"; then
        log_warn "GitHub unreachable, downloaded keys from mirror"
    else
        log_error "Failed to download SSH keys from both GitHub and mirror"
        return 1
    fi

    if [ ! -s "$ssh_dir/authorized_keys" ]; then
        log_error "Downloaded keys file is empty"
        return 1
    fi

    chmod 700 "$ssh_dir"
    chmod 600 "$ssh_dir/authorized_keys"
    chown -R "$username:$username" "$ssh_dir"

    log_info "SSH keys imported for $username"
}

# Create additional users with their SSH keys
create_additional_users() {
    if [ "$ADD_ADDITIONAL_USERS" = false ] || [ -z "$ADDITIONAL_USERS" ]; then
        return
    fi

    log_info "Creating additional users..."

    # Split semicolon-separated user entries
    IFS=';' read -ra USER_ENTRIES <<< "$ADDITIONAL_USERS"
    local success_count=0
    local fail_count=0

    for user_entry in "${USER_ENTRIES[@]}"; do
        # Trim whitespace
        user_entry=$(echo "$user_entry" | xargs)

        if [ -z "$user_entry" ]; then
            continue
        fi

        # Parse user entry: username@key_url[:sudo|:nopasswd]
        local sudo_type="none"

        # Check suffixes
        if [[ "$user_entry" == *:nopasswd ]]; then
            sudo_type="nopasswd"
            user_entry="${user_entry%:nopasswd}"
        elif [[ "$user_entry" == *:sudo ]]; then
            sudo_type="sudo"
            user_entry="${user_entry%:sudo}"
        fi

        # Split by @ to get username and key_url
        local username="${user_entry%%@*}"
        local key_url="${user_entry#*@}"

        if [ -z "$username" ] || [ -z "$key_url" ]; then
            log_warn "Invalid user entry: $user_entry (skipping)"
            fail_count=$((fail_count + 1))
            continue
        fi

        log_info "Creating user: $username"

        # Check if user already exists
        if id "$username" &>/dev/null; then
            log_warn "User $username already exists, skipping creation"
            log_info "Updating SSH keys for existing user: $username"
        else
            # Create user
            if useradd -m -s /bin/bash "$username"; then
                log_info "User $username created"
            else
                log_error "Failed to create user: $username"
                fail_count=$((fail_count + 1))
                continue
            fi
        fi

        # Configure sudo privileges
        if [ "$sudo_type" != "none" ]; then
            log_info "Adding $username to sudo group..."
            usermod -aG sudo "$username"

            if [ "$sudo_type" == "nopasswd" ]; then
                # Configure passwordless sudo
                echo "$username ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/$username
                log_info "Sudo privileges granted to $username (NOPASSWD)"
            else
                # Configure password-required sudo
                echo "$username ALL=(ALL) ALL" > /etc/sudoers.d/$username
                log_info "Sudo privileges granted to $username (password required)"
            fi
            
            chmod 0440 /etc/sudoers.d/$username
        fi

        # Import SSH keys
        local ssh_dir="/home/$username/.ssh"
        mkdir -p "$ssh_dir"


        log_info "Downloading SSH keys for $username from: $key_url"

        if curl_fetch "$key_url" "$ssh_dir/authorized_keys"; then
            # Verify keys file is not empty
            if [ -s "$ssh_dir/authorized_keys" ]; then
                # Set correct permissions
                chmod 700 "$ssh_dir"
                chmod 600 "$ssh_dir/authorized_keys"
                chown -R "$username:$username" "$ssh_dir"

                log_info "SSH keys imported for $username"
                success_count=$((success_count + 1))
            else
                log_error "Downloaded keys file is empty for $username"
                fail_count=$((fail_count + 1))
            fi
        else
            log_error "Failed to download SSH keys for $username"
            fail_count=$((fail_count + 1))
        fi
    done

    log_info "Additional users creation completed: $success_count succeeded, $fail_count failed"
}

# Disable root login
disable_root_login() {
    local sshd_config="/etc/ssh/sshd_config"

    log_info "Disabling root login via SSH..."

    # Backup original config
    cp "$sshd_config" "${sshd_config}.backup.$(date +%Y%m%d_%H%M%S)"

    # Disable root login
    if grep -q "^PermitRootLogin" "$sshd_config"; then
        sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' "$sshd_config"
    else
        echo "PermitRootLogin no" >> "$sshd_config"
    fi

    # Ensure password authentication is configured
    if grep -q "^PasswordAuthentication" "$sshd_config"; then
        sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/' "$sshd_config"
    else
        echo "PasswordAuthentication no" >> "$sshd_config"
    fi

    # Enable public key authentication
    if grep -q "^PubkeyAuthentication" "$sshd_config"; then
        sed -i 's/^PubkeyAuthentication.*/PubkeyAuthentication yes/' "$sshd_config"
    else
        echo "PubkeyAuthentication yes" >> "$sshd_config"
    fi

    log_info "Root login disabled"
    log_warn "SSH service will be restarted at the end of the script"
}

# Install zsh and oh-my-zsh
install_zsh() {
    local username="arcat"
    local user_home="/home/$username"

    log_info "Installing zsh..."
    $PKG_INSTALL zsh git curl

    # Check if oh-my-zsh is already installed
    if [ -d "${user_home}/.oh-my-zsh" ]; then
        log_warn "oh-my-zsh is already installed for $username, skipping installation"
    else
        log_info "Installing oh-my-zsh for $username..."
        # Install oh-my-zsh as the user
        local omz_install_url="https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh"
        if is_cn_machine; then
            omz_install_url="https://gitee.com/mirrors/oh-my-zsh/raw/master/tools/install.sh"
        fi
        local omz_install_script="/tmp/ohmyzsh-install.sh"
        if curl_fetch "$omz_install_url" "$omz_install_script"; then
            chmod +x "$omz_install_script"
            su - "$username" -c "sh '$omz_install_script' \"\" --unattended"
        else
            log_error "Failed to download oh-my-zsh installer from $omz_install_url"
        fi
    fi

    # Install useful plugins
    log_info "Installing zsh plugins..."

    # zsh-autosuggestions
    if [ -d "${user_home}/.oh-my-zsh/custom/plugins/zsh-autosuggestions" ]; then
        log_warn "zsh-autosuggestions is already installed, skipping"
    else
        local autosuggest_repo="https://github.com/zsh-users/zsh-autosuggestions"
        if is_cn_machine; then
            autosuggest_repo="${CN_GIT_MIRROR_BASE}/zsh-autosuggestions"
        fi
        su - "$username" -c "git clone ${autosuggest_repo} ${user_home}/.oh-my-zsh/custom/plugins/zsh-autosuggestions"
    fi

    # zsh-syntax-highlighting
    if [ -d "${user_home}/.oh-my-zsh/custom/plugins/zsh-syntax-highlighting" ]; then
        log_warn "zsh-syntax-highlighting is already installed, skipping"
    else
        local syntax_repo="https://github.com/zsh-users/zsh-syntax-highlighting.git"
        if is_cn_machine; then
            syntax_repo="${CN_GIT_MIRROR_BASE}/zsh-syntax-highlighting.git"
        fi
        su - "$username" -c "git clone ${syntax_repo} ${user_home}/.oh-my-zsh/custom/plugins/zsh-syntax-highlighting"
    fi

    # Configure .zshrc with recommended plugins
    log_info "Configuring zsh plugins..."
    su - "$username" -c "sed -i 's/^plugins=(git)/plugins=(git sudo zsh-autosuggestions zsh-syntax-highlighting colored-man-pages command-not-found)/' ${user_home}/.zshrc"

    # Install and configure starship
    log_info "Installing starship prompt..."
    if $PKG_INSTALL starship; then
        log_info "Starship installed"
    else
        log_error "Failed to install starship via apt"
    fi

    # Create config directory
    su - "$username" -c "mkdir -p ${user_home}/.config"

    # Apply plain-text-symbols preset
    log_info "Configuring starship with plain-text-symbols preset..."
    su - "$username" -c "starship preset plain-text-symbols -o ${user_home}/.config/starship.toml"

    # Add starship initialization to .zshrc
    log_info "Adding starship to .zshrc..."
    su - "$username" -c "echo '' >> ${user_home}/.zshrc"
    su - "$username" -c "echo '# Initialize starship prompt' >> ${user_home}/.zshrc"
    su - "$username" -c "echo 'eval \"\$(starship init zsh)\"' >> ${user_home}/.zshrc"

    # Change default shell to zsh
    log_info "Setting zsh as default shell for $username..."
    chsh -s $(which zsh) "$username"

    log_info "Zsh, oh-my-zsh, and starship installed successfully"
}

# Install direnv
install_direnv() {
    local username="arcat"
    local user_home="/home/$username"

    log_info "Installing direnv..."
    $PKG_INSTALL direnv

    # Add direnv hook to .zshrc
    log_info "Configuring direnv for zsh..."
    su - "$username" -c "echo 'eval \"\$(direnv hook zsh)\"' >> ${user_home}/.zshrc"

    log_info "Direnv installed successfully"
}

# Install mosh
install_mosh() {
    log_info "Installing mosh..."
    $PKG_INSTALL mosh

    log_info "Mosh installed successfully"
}

ensure_iptables_nft_backend() {
    # UFW uses iptables tooling; we prefer iptables-nft so rules are managed by nftables backend.
    if ! command -v update-alternatives &>/dev/null; then
        log_warn "update-alternatives not found; cannot force iptables-nft backend"
        return 0
    fi

    local changed=false
    local alt_name alt_target

    for alt_name in iptables ip6tables arptables ebtables; do
        alt_target="${alt_name}-nft"
        if command -v "$alt_target" &>/dev/null; then
            if update-alternatives --set "$alt_name" "$(command -v "$alt_target")" >/dev/null 2>&1; then
                changed=true
            else
                log_warn "Failed to set $alt_name alternative to $alt_target"
            fi
        else
            log_warn "$alt_target not found; cannot set $alt_name to nft backend"
        fi
    done

    if command -v iptables &>/dev/null; then
        local iptables_ver
        iptables_ver="$(iptables -V 2>/dev/null || true)"
        if echo "$iptables_ver" | grep -qi "nf_tables"; then
            log_info "iptables backend: nf_tables"
        else
            log_warn "iptables may not be using nf_tables backend: ${iptables_ver:-unknown}"
        fi
    fi

    if [ "$changed" = true ]; then
        log_info "Configured iptables alternatives to use nft backend (where available)"
    fi
}

# Configure nftables firewall (default)
configure_nftables() {
    log_info "Configuring nftables firewall..."

    if ! command -v nft &>/dev/null; then
        log_info "Installing nftables..."
        $PKG_INSTALL nftables
    fi

    # Detect SSH port from sshd_config
    local ssh_port
    ssh_port=$(grep -E "^Port " /etc/ssh/sshd_config | awk '{print $2}' | head -n1)
    if [ -z "$ssh_port" ]; then
        ssh_port=22
    fi

    log_info "Detected SSH port: $ssh_port"

    # Disable ufw if active to avoid conflicting rulesets.
    if command -v ufw &>/dev/null; then
        if ufw status 2>/dev/null | grep -q "Status: active"; then
            log_warn "UFW is active; disabling it because firewall backend is nftables"
            ufw --force disable || log_warn "Failed to disable UFW"
        fi
    fi

    local nft_conf="/etc/nftables.conf"
    local managed_marker="Managed by server-init.sh"

    if [ -r "$nft_conf" ] && grep -q "$managed_marker" "$nft_conf"; then
        log_info "Existing nftables config managed by this script; updating rules"
    else
        if nft list ruleset 2>/dev/null | grep -q .; then
            log_info "nftables already has rules; preserving existing ruleset"
            log_warn "Skipping nftables rule changes; ensure SSH ($ssh_port/tcp) and Mosh (60000-61000/udp) are allowed"
            SERVICE_ENABLE nftables
            SERVICE_START nftables || true
            return
        fi
    fi

    if [ -e "$nft_conf" ]; then
        cp "$nft_conf" "${nft_conf}.backup.$(date +%Y%m%d_%H%M%S)"
    fi

    cat > "$nft_conf" <<EOF
#!/usr/sbin/nft -f
# ${managed_marker}

flush ruleset

table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;

    iif lo accept
    ct state established,related accept

    ip protocol icmp accept
    ip6 nexthdr icmpv6 accept

    tcp dport ${ssh_port} accept comment "SSH"
    udp dport 60000-61000 accept comment "Mosh"

    # Uncomment if you want to host web services:
    # tcp dport 80 accept comment "HTTP"
    # tcp dport 443 accept comment "HTTPS"
  }

  chain forward {
    type filter hook forward priority 0; policy drop;
  }

  chain output {
    type filter hook output priority 0; policy accept;
  }
}
EOF

    # Enable and apply
    SERVICE_ENABLE nftables
    SERVICE_START nftables || true
    SERVICE_RELOAD nftables || true

    log_info "nftables configuration completed. Current ruleset:"
    nft list ruleset || log_warn "Failed to list nftables ruleset"
    log_warn "Firewall is active. Ensure port $ssh_port (SSH) is accessible."
}

# Configure UFW firewall
configure_ufw() {
    log_info "Configuring UFW firewall..."

    # Install ufw if not present
    if ! command -v ufw &>/dev/null; then
        log_info "Installing UFW..."
        $PKG_INSTALL ufw
    fi

    # Ensure UFW uses nftables backend via iptables-nft.
    ensure_iptables_nft_backend

    # Detect SSH port from sshd_config
    local ssh_port=$(grep -E "^Port " /etc/ssh/sshd_config | awk '{print $2}')
    if [ -z "$ssh_port" ]; then
        ssh_port=22
    fi

    log_info "Detected SSH port: $ssh_port"

    # Check if UFW is already active
    if ufw status | grep -q "Status: active"; then
        log_info "UFW is already active. Preserving existing rules."
    else
        # Disable UFW first to avoid issues
        ufw --force disable

        # Reset UFW to default
        log_info "Resetting UFW to default configuration..."
        ufw --force reset

        # Set default policies
        log_info "Setting default policies (deny incoming, allow outgoing)..."
        ufw default deny incoming
        ufw default allow outgoing
    fi

    # Allow SSH (critical - must be first!)
    log_info "Ensuring SSH is allowed on port $ssh_port..."
    ufw allow $ssh_port/tcp comment 'SSH'

    # Allow HTTP
    # log_info "Ensuring HTTP (port 80) is allowed..."
    # ufw allow 80/tcp comment 'HTTP'

    # Allow HTTPS
    # log_info "Ensuring HTTPS (port 443) is allowed..."
    # ufw allow 443/tcp comment 'HTTPS'

    # Allow Mosh
    log_info "Ensuring Mosh (UDP ports 60000-61000) is allowed..."
    ufw allow 60000:61000/udp comment 'Mosh'

    # Enable UFW if not already enabled
    if ! ufw status | grep -q "Status: active"; then
        log_info "Enabling UFW..."
        ufw --force enable
    fi

    # Show status
    log_info "UFW configuration completed. Current status:"
    ufw status verbose

    log_warn "Firewall is active. Ensure port $ssh_port (SSH) is accessible."
}

configure_firewall() {
    case "$FIREWALL" in
        nftables) configure_nftables ;;
        ufw) configure_ufw ;;
        *)
            log_warn "Unknown firewall '$FIREWALL', defaulting to nftables"
            configure_nftables
            ;;
    esac
}

# Install and configure CrowdSec
install_crowdsec() {
    log_info "Installing CrowdSec for intrusion prevention..."

    # Check if CrowdSec is already installed
    if command -v cscli &>/dev/null; then
        log_warn "CrowdSec is already installed, skipping installation"
        return
    fi

    # Add CrowdSec repository using official script
    log_info "Adding CrowdSec repository..."
    local crowdsec_install_url="https://install.crowdsec.net"
    local crowdsec_install_script="/tmp/crowdsec-install.sh"
    if curl_fetch "$crowdsec_install_url" "$crowdsec_install_script"; then
        sh "$crowdsec_install_script"
    else
        log_error "Failed to download CrowdSec installer from $crowdsec_install_url"
        return 1
    fi
    
    # Update package lists to ensure the new repository is recognized
    log_info "Updating package lists..."
    $PKG_UPDATE

    # Install CrowdSec
    log_info "Installing CrowdSec..."
    $PKG_INSTALL crowdsec

    # Install firewall bouncer
    log_info "Installing CrowdSec firewall bouncer..."
    local bouncer_pkg="crowdsec-firewall-bouncer-nftables"
    if [ "$FIREWALL" = "ufw" ]; then
        bouncer_pkg="crowdsec-firewall-bouncer-iptables"
    fi

    if ! $PKG_INSTALL "$bouncer_pkg"; then
        log_warn "Failed to install $bouncer_pkg"
        if [ "$bouncer_pkg" != "crowdsec-firewall-bouncer-iptables" ]; then
            log_warn "Falling back to crowdsec-firewall-bouncer-iptables"
            $PKG_INSTALL crowdsec-firewall-bouncer-iptables
        else
            return 1
        fi
    fi

    # Enable and start CrowdSec service
    log_info "Enabling CrowdSec service..."
    SERVICE_ENABLE crowdsec
    SERVICE_START crowdsec

    # Wait for CrowdSec to initialize
    sleep 5

    # Install SSH collection (should be installed by default, but ensure it)
    log_info "Ensuring SSH protection collection is installed..."
    cscli collections install crowdsecurity/sshd || log_warn "SSH collection may already be installed"

    # Install Linux base collection
    log_info "Installing Linux base collection..."
    cscli collections install crowdsecurity/linux || log_warn "Linux collection may already be installed"

    # Reload CrowdSec to apply collections
    log_info "Reloading CrowdSec..."
    SERVICE_RELOAD crowdsec

    # Show CrowdSec status
    log_info "CrowdSec installation completed. Status:"
    cscli metrics

    log_info "CrowdSec is now protecting your server against SSH brute-force and other attacks"
    log_info "You can view alerts with: sudo cscli alerts list"
    log_info "You can view decisions (bans) with: sudo cscli decisions list"
}

# Enable BBR if supported
enable_bbr() {
    log_info "Checking BBR support..."

    # Check kernel version (BBR requires kernel 4.9+)
    kernel_version=$(uname -r | cut -d. -f1,2)
    kernel_major=$(echo $kernel_version | cut -d. -f1)
    kernel_minor=$(echo $kernel_version | cut -d. -f2)

    if [ "$kernel_major" -lt 4 ] || ([ "$kernel_major" -eq 4 ] && [ "$kernel_minor" -lt 9 ]); then
        log_warn "Kernel version $kernel_version does not support BBR (requires 4.9+)"
        return
    fi

    # Check if BBR module is available
    if ! modinfo tcp_bbr &>/dev/null; then
        log_warn "BBR module not available in this kernel"
        return
    fi

    log_info "BBR is supported on this system"

    # Check if BBR is already enabled
    current_congestion=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "")
    if [ "$current_congestion" = "bbr" ]; then
        log_info "BBR is already enabled"
        return
    fi

    # Enable BBR
    log_info "Enabling BBR..."

    # Load BBR module
    modprobe tcp_bbr

    # Configure sysctl
    cat >> /etc/sysctl.conf <<EOF

# BBR congestion control
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF

    # Apply sysctl settings
    sysctl -p

    # Verify BBR is enabled
    if [ "$(sysctl -n net.ipv4.tcp_congestion_control)" = "bbr" ]; then
        log_info "BBR enabled successfully"
    else
        log_warn "Failed to enable BBR"
    fi
}

# Restart SSH service
restart_ssh() {
    log_info "Restarting SSH service..."
    # Use detected service manager, try common ssh service names.
    SERVICE_RESTART sshd || SERVICE_RESTART ssh || log_warn "Failed to restart SSH service"
    log_info "SSH service restarted"
}

# Main execution
main() {
    log_info "Starting server initialization..."
    echo ""

    # Parse command line arguments
    parse_arguments "$@"

    detect_os
    apply_cn_proxy_env
    fix_hostname
    report_cn_optimization

    # Prompt for additional users if not specified via command line
    prompt_additional_users

    update_system

    if is_cn_machine; then
        if ! prompt_dae_subscription; then
            exit 1
        fi
        install_dae
        configure_dae
    fi

    create_user
    import_ssh_keys
    create_additional_users
    disable_root_login
    if ! is_cn_machine; then
        install_zsh
        install_direnv
        install_mosh
        configure_firewall
        install_crowdsec
        enable_bbr
    fi
    restart_ssh

    echo ""
    log_info "=========================================="
    log_info "Server initialization completed!"
    log_info "=========================================="
    log_info "User 'arcat' has been created with sudo privileges"
    log_info "SSH keys imported from GitHub"

    if [ "$ADD_ADDITIONAL_USERS" = true ]; then
        log_info "Additional users have been created (if any)"
    fi

    log_info "Hostname resolution has been configured"
    log_info "Root login has been disabled"
    if is_cn_machine; then
        log_info "dae has been installed and configured"
        log_info "dae config location: /usr/local/etc/dae/config.dae"
    else
        log_info "Zsh with oh-my-zsh has been installed"
        log_info "Starship prompt has been configured with plain-text-symbols preset"
        log_info "Direnv has been installed and configured"
        log_info "Mosh has been installed for better remote connections"
        log_info "Firewall has been configured and enabled ($FIREWALL)"
        log_info "CrowdSec has been installed for intrusion prevention"
        log_info "BBR has been checked and enabled if supported"
    fi
    log_info ""
    log_warn "IMPORTANT: Please test SSH login with user 'arcat' before closing this session!"
    log_info ""
    if ! is_cn_machine; then
        log_info "You can also connect using: mosh arcat@your-server-ip"
        log_info ""
        log_info "CrowdSec commands:"
        log_info "  - View alerts: sudo cscli alerts list"
        log_info "  - View bans: sudo cscli decisions list"
        log_info "  - View metrics: sudo cscli metrics"
    fi
    log_info "=========================================="
}

main "$@"
