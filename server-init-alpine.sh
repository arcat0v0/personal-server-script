#!/bin/sh

#############################################
# Server Initialization Script (Alpine Linux)
# Supports: Alpine Linux
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
# - Configure nftables firewall
# - Install and configure CrowdSec for intrusion prevention
# - Enable BBR if supported
# - CN mode: install dae after base tools and skip optional installers
#############################################

set -e

ADDITIONAL_USERS=""
ADD_ADDITIONAL_USERS=false
DAE_SUBSCRIPTION_URL=""
DAE_CONFIG_TEMPLATE_URL="https://raw.githubusercontent.com/arcat0v0/personal-server-script/main/config-template.dae"

CN_HTTP_PROXY="${CN_HTTP_PROXY:-}"
CN_PROXY_PREFIX="${CN_PROXY_PREFIX:-https://ghfast.top/}"
CN_GIT_MIRROR_BASE="${CN_GIT_MIRROR_BASE:-https://gitee.com/mirrors}"

IS_CN_MACHINE=""
FORCE_CN="${FORCE_CN:-}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() {
    printf "${GREEN}[INFO]${NC} %s\n" "$1"
}

log_warn() {
    printf "${YELLOW}[WARN]${NC} %s\n" "$1"
}

log_error() {
    printf "${RED}[ERROR]${NC} %s\n" "$1"
}

has_cmd() {
    command -v "$1" >/dev/null 2>&1
}

can_prompt() {
    test -t 0
}

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
        return 1
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
    local proxy_arg=""

    if is_cn_machine && [ -n "$CN_HTTP_PROXY" ]; then
        proxy_arg="--proxy $CN_HTTP_PROXY"
        final_url="$url"
    else
        final_url="$(proxy_url "$url")"
    fi

    if [ -n "$output" ]; then
        curl -fsSL --connect-timeout 10 --max-time 30 $proxy_arg "$final_url" -o "$output"
    else
        curl -fsSL --connect-timeout 10 --max-time 30 $proxy_arg "$final_url"
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

    if ! can_prompt; then
        log_error "No TTY available. Use --dae-sub URL to provide the subscription URL."
        return 1
    fi

    echo ""
    log_info "CN mode detected: dae will be installed and configured"
    printf "%b" "${YELLOW}[PROMPT]${NC} Enter dae subscription URL (my_sub): " > /dev/tty
    if ! read -r REPLY < /dev/tty; then
        return 1
    fi
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

    escaped_sub=$(printf '%s' "$DAE_SUBSCRIPTION_URL" | sed -e 's/\\/\\\\/g' -e 's/&/\\&/g' -e 's/#/\\#/g')

    mkdir -p "$config_dir"
    cp "$config_src" "$config_path"
    sed -i "s#^\\(\\s*my_sub:\\s*\\).*\$#\\1'${escaped_sub}'#" "$config_path"
    log_info "dae config written to $config_path"
}

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

    if [ "$OS_ID" = "alpine" ]; then
        log_info "Detected OS: $OS_ID $OS_VERSION"
    else
        log_warn "Unsupported OS: $OS_ID $OS_VERSION. Will try to continue best-effort."
    fi

    if has_cmd apk; then
        PKG_UPDATE="apk update"
        PKG_INSTALL="apk add"
    else
        log_error "No supported package manager found (apk)."
        exit 1
    fi

    if ! has_cmd curl; then
        log_info "curl not found, installing..."
        $PKG_UPDATE
        $PKG_INSTALL curl ca-certificates
    fi

    if has_cmd rc-service; then
        SERVICE_RESTART() { rc-service "$1" restart; }
        SERVICE_START() { rc-service "$1" start; }
        SERVICE_ENABLE() { rc-update add "$1" default >/dev/null 2>&1 || true; }
        SERVICE_RELOAD() { rc-service "$1" reload || rc-service "$1" restart; }
    else
        log_warn "rc-service not found. Service operations may fail."
        SERVICE_RESTART() { log_warn "Skipping restart for $1"; }
        SERVICE_START() { log_warn "Skipping start for $1"; }
        SERVICE_ENABLE() { log_warn "Skipping enable for $1"; }
        SERVICE_RELOAD() { log_warn "Skipping reload for $1"; }
    fi
}

parse_arguments() {
    while [ $# -gt 0 ]; do
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
            -h|--help)
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  -a, --add-users         Enable adding additional users (will prompt for details)"
                echo "  -u, --users USERS       Specify additional users (semicolon-separated)"
                echo "      --dae-sub URL       Set dae subscription URL (my_sub)"
                echo "      --cn                Force China optimized addresses"
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

prompt_additional_users() {
    if [ "$ADD_ADDITIONAL_USERS" = false ]; then
        if ! can_prompt; then
            return 0
        fi
        echo ""
        printf "%b" "${YELLOW}[PROMPT]${NC} Do you want to create additional users? (y/N): " > /dev/tty
        if ! read -r REPLY < /dev/tty; then
            return 0
        fi
        case "$REPLY" in
            [Yy]*) ADD_ADDITIONAL_USERS=true ;;
            *) return 0 ;;
        esac
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
            printf "%b" "${YELLOW}[PROMPT]${NC} Enter username: " > /dev/tty
            if ! read -r username < /dev/tty; then
                break
            fi

            if [ -z "$username" ]; then
                log_warn "Username cannot be empty"
                continue
            fi

            printf "%b" "${YELLOW}[PROMPT]${NC} Enter SSH key URL for $username: " > /dev/tty
            if ! read -r key_url < /dev/tty; then
                break
            fi

            if [ -z "$key_url" ]; then
                log_warn "Key URL cannot be empty"
                continue
            fi

            printf "%b" "${YELLOW}[PROMPT]${NC} Should $username have sudo privileges? (y/N): " > /dev/tty
            if ! read -r sudo_choice < /dev/tty; then
                sudo_choice=""
            fi

            local priv_suffix=""
            case "$sudo_choice" in
                [Yy]*)
                    printf "%b" "${YELLOW}[PROMPT]${NC} Enable passwordless sudo (NOPASSWD) for $username? (y/N): " > /dev/tty
                    if ! read -r nopasswd_choice < /dev/tty; then
                        nopasswd_choice=""
                    fi
                    case "$nopasswd_choice" in
                        [Yy]*) priv_suffix=":nopasswd" ;;
                        *) priv_suffix=":sudo" ;;
                    esac
                    ;;
            esac

            if [ -z "$user_entries" ]; then
                user_entries="${username}@${key_url}${priv_suffix}"
            else
                user_entries="${user_entries};${username}@${key_url}${priv_suffix}"
            fi

            log_info "Added user: $username${priv_suffix}"

            echo ""
            printf "%b" "${YELLOW}[PROMPT]${NC} Add another user? (y/N): " > /dev/tty
            if ! read -r continue_choice < /dev/tty; then
                break
            fi
            case "$continue_choice" in
                [Yy]*) continue_adding=true ;;
                *) continue_adding=false ;;
            esac
        done

        ADDITIONAL_USERS="$user_entries"

        if [ -z "$ADDITIONAL_USERS" ]; then
            log_warn "No users provided, skipping additional users"
            ADD_ADDITIONAL_USERS=false
        fi
    fi
}

sed_inplace() {
    local expr="$1" file="$2" tmp
    tmp=$(mktemp)
    sed "$expr" "$file" > "$tmp" && cat "$tmp" > "$file"
    rm -f "$tmp"
}

fix_hostname() {
    log_info "Fixing hostname resolution..."

    local hostname
    hostname="$(hostname)"

    if [ -z "$hostname" ]; then
        log_warn "Unable to determine hostname, skipping"
        return
    fi

    local hosts_file="/etc/hosts"
    cp "$hosts_file" "${hosts_file}.backup.$(date +%Y%m%d_%H%M%S)" 2>/dev/null || true

    if grep -qE "^127\.0\.0\.1[[:space:]]+" "$hosts_file"; then
        if ! grep -qE "^127\.0\.0\.1[[:space:]].*\blocalhost\b" "$hosts_file"; then
            sed_inplace "s/^127\.0\.0\.1[[:space:]]\+\(.*\)$/127.0.0.1\tlocalhost \1/" "$hosts_file"
        fi
    else
        printf "127.0.0.1\tlocalhost\n" >> "$hosts_file"
    fi

    if grep -qE "^127\.0\.0\.1[[:space:]].*\b${hostname}\b" "$hosts_file"; then
        log_info "Hostname already resolvable on 127.0.0.1"
        return
    fi

    if grep -qE "^127\.0\.0\.1[[:space:]]+" "$hosts_file"; then
        sed_inplace "s/^127\.0\.0\.1[[:space:]]\+\(.*\)$/127.0.0.1\t\1 ${hostname}/" "$hosts_file"
    else
        printf "127.0.0.1\tlocalhost ${hostname}\n" >> "$hosts_file"
    fi

    log_info "Hostname resolution fixed for: $hostname"
}

install_common_tools() {
    log_info "Installing common tools..."

    $PKG_INSTALL \
        vim \
        nano \
        less \
        htop \
        tmux \
        unzip \
        zip \
        rsync \
        lsof \
        net-tools \
        jq \
        wget \
        git \
        ca-certificates \
        gnupg \
        sudo \
        shadow

    if grep -qE "^[[:space:]]*%wheel[[:space:]]+ALL=\(ALL:ALL\)[[:space:]]+ALL" /etc/sudoers; then
        :
    elif grep -qE "^[[:space:]]*#[[:space:]]*%wheel[[:space:]]+ALL=\(ALL:ALL\)[[:space:]]+ALL" /etc/sudoers; then
        sed -i "s/^[[:space:]]*#[[:space:]]*\(%wheel[[:space:]]\+ALL=(ALL:ALL)[[:space:]]\+ALL\)/\1/" /etc/sudoers
    else
        printf "\n%%wheel ALL=(ALL:ALL) ALL\n" >> /etc/sudoers
    fi

    log_info "Common tools installed"
}

update_system() {
    log_info "Updating system packages..."

    apk update
    apk upgrade

    install_common_tools
    log_info "System update completed"
}

create_user() {
    local username="arcat"

    log_info "Creating main user: $username"

    if id "$username" >/dev/null 2>&1; then
        log_warn "User $username already exists, skipping creation"
    else
        adduser -D -s /bin/sh "$username"
        sed -i "s/^${username}:!:/${username}:*:/" /etc/shadow
        log_info "User $username created"
    fi

    addgroup "$username" wheel

    echo "$username ALL=(ALL) NOPASSWD:ALL" > "/etc/sudoers.d/$username"
    chmod 0440 "/etc/sudoers.d/$username"

    log_info "User $username granted sudo privileges (NOPASSWD)"
}

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

    chown "$username:$username" "/home/$username"
    chmod 755 "/home/$username"
    chmod 700 "$ssh_dir"
    chmod 600 "$ssh_dir/authorized_keys"
    chown -R "$username:$username" "$ssh_dir"

    log_info "SSH keys imported for $username"
}

create_additional_users() {
    if [ "$ADD_ADDITIONAL_USERS" = false ] || [ -z "$ADDITIONAL_USERS" ]; then
        return
    fi

    log_info "Creating additional users..."

    local success_count=0
    local fail_count=0
    local old_ifs="$IFS"

    IFS=';'
    for user_entry in $ADDITIONAL_USERS; do
        IFS="$old_ifs"
        user_entry=$(printf "%s" "$user_entry" | xargs)

        if [ -z "$user_entry" ]; then
            IFS=';'
            continue
        fi

        local sudo_type="none"
        case "$user_entry" in
            *:nopasswd)
                sudo_type="nopasswd"
                user_entry="${user_entry%:nopasswd}"
                ;;
            *:sudo)
                sudo_type="sudo"
                user_entry="${user_entry%:sudo}"
                ;;
        esac

        local username="${user_entry%%@*}"
        local key_url="${user_entry#*@}"

        if [ -z "$username" ] || [ -z "$key_url" ]; then
            log_warn "Invalid user entry: $user_entry (skipping)"
            fail_count=$((fail_count + 1))
            IFS=';'
            continue
        fi

        log_info "Creating user: $username"

        if id "$username" >/dev/null 2>&1; then
            log_warn "User $username already exists, skipping creation"
            log_info "Updating SSH keys for existing user: $username"
        else
            if adduser -D -s /bin/sh "$username"; then
                sed -i "s/^${username}:!:/${username}:*:/" /etc/shadow
                log_info "User $username created"
            else
                log_error "Failed to create user: $username"
                fail_count=$((fail_count + 1))
                IFS=';'
                continue
            fi
        fi

        if [ "$sudo_type" != "none" ]; then
            log_info "Adding $username to wheel group..."
            addgroup "$username" wheel

            if [ "$sudo_type" = "nopasswd" ]; then
                echo "$username ALL=(ALL) NOPASSWD:ALL" > "/etc/sudoers.d/$username"
                log_info "Sudo privileges granted to $username (NOPASSWD)"
            else
                echo "$username ALL=(ALL) ALL" > "/etc/sudoers.d/$username"
                log_info "Sudo privileges granted to $username (password required)"
            fi

            chmod 0440 "/etc/sudoers.d/$username"
        fi

        local ssh_dir="/home/$username/.ssh"
        mkdir -p "$ssh_dir"

        log_info "Downloading SSH keys for $username from: $key_url"

        if curl_fetch "$key_url" "$ssh_dir/authorized_keys"; then
            if [ -s "$ssh_dir/authorized_keys" ]; then
                chown "$username:$username" "/home/$username"
                chmod 755 "/home/$username"
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

        IFS=';'
    done

    IFS="$old_ifs"
    log_info "Additional users creation completed: $success_count succeeded, $fail_count failed"
}

disable_root_login() {
    local sshd_config="/etc/ssh/sshd_config"

    log_info "Disabling root login via SSH..."

    cp "$sshd_config" "${sshd_config}.backup.$(date +%Y%m%d_%H%M%S)"

    if grep -q "^PermitRootLogin" "$sshd_config"; then
        sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' "$sshd_config"
    else
        echo "PermitRootLogin no" >> "$sshd_config"
    fi

    if grep -q "^PasswordAuthentication" "$sshd_config"; then
        sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/' "$sshd_config"
    else
        echo "PasswordAuthentication no" >> "$sshd_config"
    fi

    if grep -q "^PubkeyAuthentication" "$sshd_config"; then
        sed -i 's/^PubkeyAuthentication.*/PubkeyAuthentication yes/' "$sshd_config"
    else
        echo "PubkeyAuthentication yes" >> "$sshd_config"
    fi

    log_info "Root login disabled"
    log_warn "SSH service will be restarted at the end of the script"
}

install_zsh() {
    local username="arcat"
    local user_home="/home/$username"

    log_info "Installing zsh..."
    $PKG_INSTALL zsh git curl

    if [ -d "${user_home}/.oh-my-zsh" ]; then
        log_warn "oh-my-zsh is already installed for $username, skipping installation"
    else
        log_info "Installing oh-my-zsh for $username..."
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

    log_info "Installing zsh plugins..."

    if [ -d "${user_home}/.oh-my-zsh/custom/plugins/zsh-autosuggestions" ]; then
        log_warn "zsh-autosuggestions is already installed, skipping"
    else
        local autosuggest_repo="https://github.com/zsh-users/zsh-autosuggestions"
        if is_cn_machine; then
            autosuggest_repo="${CN_GIT_MIRROR_BASE}/zsh-autosuggestions"
        fi
        su - "$username" -c "git clone ${autosuggest_repo} ${user_home}/.oh-my-zsh/custom/plugins/zsh-autosuggestions"
    fi

    if [ -d "${user_home}/.oh-my-zsh/custom/plugins/zsh-syntax-highlighting" ]; then
        log_warn "zsh-syntax-highlighting is already installed, skipping"
    else
        local syntax_repo="https://github.com/zsh-users/zsh-syntax-highlighting.git"
        if is_cn_machine; then
            syntax_repo="${CN_GIT_MIRROR_BASE}/zsh-syntax-highlighting.git"
        fi
        su - "$username" -c "git clone ${syntax_repo} ${user_home}/.oh-my-zsh/custom/plugins/zsh-syntax-highlighting"
    fi

    log_info "Configuring zsh plugins..."
    su - "$username" -c "sed -i 's/^plugins=(git)/plugins=(git sudo zsh-autosuggestions zsh-syntax-highlighting colored-man-pages)/' ${user_home}/.zshrc"

    log_info "Installing starship prompt..."
    local starship_install_script="/tmp/starship-install.sh"
    if curl_fetch "https://starship.rs/install.sh" "$starship_install_script"; then
        sh "$starship_install_script" --yes
        log_info "Starship installed"
    else
        log_error "Failed to download starship installer"
    fi

    su - "$username" -c "mkdir -p ${user_home}/.config"

    log_info "Configuring starship with plain-text-symbols preset..."
    su - "$username" -c "starship preset plain-text-symbols -o ${user_home}/.config/starship.toml"

    log_info "Adding starship to .zshrc..."
    su - "$username" -c "echo '' >> ${user_home}/.zshrc"
    su - "$username" -c "echo '# Initialize starship prompt' >> ${user_home}/.zshrc"
    su - "$username" -c "echo 'eval \"\$(starship init zsh)\"' >> ${user_home}/.zshrc"

    log_info "Setting zsh as default shell for $username..."
    chsh -s "$(command -v zsh)" "$username"

    log_info "Zsh, oh-my-zsh, and starship installed successfully"
}

install_direnv() {
    local username="arcat"
    local user_home="/home/$username"

    log_info "Installing direnv..."
    $PKG_INSTALL direnv

    log_info "Configuring direnv for zsh..."
    su - "$username" -c "echo 'eval \"\$(direnv hook zsh)\"' >> ${user_home}/.zshrc"

    log_info "Direnv installed successfully"
}

install_mosh() {
    log_info "Installing mosh..."
    $PKG_INSTALL mosh

    log_info "Mosh installed successfully"
}

sanitize_crowdsec_online_credentials() {
    local capi_credentials="/etc/crowdsec/online_api_credentials.yaml"
    local capi_url="https://api.crowdsec.net/"

    if [ -f "$capi_credentials" ]; then
        local detected_url=""
        detected_url=$(awk '/^[[:space:]]*url:[[:space:]]*[^[:space:]]+/ {print $2; exit}' "$capi_credentials" 2>/dev/null || true)
        if [ -n "$detected_url" ]; then
            capi_url="$detected_url"
        fi
    fi

    if [ -f "$capi_credentials" ] \
        && grep -qE '^[[:space:]]*login:[[:space:]]*[^[:space:]]+' "$capi_credentials" \
        && grep -qE '^[[:space:]]*password:[[:space:]]*[^[:space:]]+' "$capi_credentials"; then
        return
    fi

    if [ -f "$capi_credentials" ]; then
        local backup_path="${capi_credentials}.backup.$(date +%Y%m%d_%H%M%S)"
        cp "$capi_credentials" "$backup_path"
        log_warn "Invalid CrowdSec online_api_credentials.yaml; backup saved to $backup_path"
    fi

    cat > "$capi_credentials" <<EOF
url: $capi_url
EOF

    log_info "Wrote minimal CrowdSec online API credentials (CAPI disabled)"
}

ensure_crowdsec_acquisition_datasource() {
    local acquis_file="/etc/crowdsec/acquis.yaml"

    if [ -f "$acquis_file" ] && grep -qE '^[[:space:]]*(source|journalctl_filter|filenames)[[:space:]]*:' "$acquis_file"; then
        return
    fi

    if [ -f "$acquis_file" ]; then
        local backup_path="${acquis_file}.backup.$(date +%Y%m%d_%H%M%S)"
        cp "$acquis_file" "$backup_path"
        log_warn "CrowdSec acquisition config had no datasource; backup saved to $backup_path"
    fi

    cat > "$acquis_file" <<'EOF'
filenames:
  - /var/log/auth.log
  - /var/log/secure
  - /var/log/messages
labels:
  type: syslog
EOF

    log_info "Configured default CrowdSec acquisition datasource in $acquis_file"
}

configure_nftables() {
    log_info "Configuring nftables firewall..."

    if ! command -v nft >/dev/null 2>&1; then
        log_info "Installing nftables..."
        $PKG_INSTALL nftables
    fi

    local ssh_port
    ssh_port=$(grep -E "^Port " /etc/ssh/sshd_config | awk 'NR==1 {print $2}')
    if [ -z "$ssh_port" ]; then
        ssh_port=22
    fi

    log_info "Detected SSH port: $ssh_port"

    mkdir -p /etc/nftables.d

    cat > /etc/nftables.d/server-init.nft <<EOF
table inet filter {
  chain input {
    tcp dport $ssh_port accept comment "SSH"
    udp dport 60000-61000 accept comment "Mosh"
  }
}
EOF

    SERVICE_ENABLE nftables
    SERVICE_RESTART nftables || true

    log_info "nftables configuration completed. Current ruleset:"
    nft list ruleset || log_warn "Failed to list nftables ruleset"
    log_warn "Firewall is active. Ensure port $ssh_port (SSH) is accessible."
}

wait_for_crowdsec_lapi() {
    local max_attempts=15
    local attempt=0
    while [ "$attempt" -lt "$max_attempts" ]; do
        if curl -sf http://127.0.0.1:8080/health >/dev/null 2>&1; then
            return 0
        fi
        attempt=$((attempt + 1))
        sleep 2
    done
    log_warn "CrowdSec LAPI did not become ready after $((max_attempts * 2))s"
    return 1
}

configure_crowdsec_bouncer() {
    local bouncer_config="/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml"

    if [ ! -f "$bouncer_config" ]; then
        log_warn "Bouncer config not found at $bouncer_config"
        return 1
    fi

    log_info "Setting bouncer mode to nftables..."
    sed_inplace "s/^mode: .*$/mode: nftables/" "$bouncer_config"

    local existing_key
    existing_key=$(awk '/^api_key:/ {print $2}' "$bouncer_config" | tr -d '[:space:]')
    if [ -n "$existing_key" ]; then
        log_info "Bouncer already has an API key, skipping registration"
        return 0
    fi

    log_info "Registering firewall bouncer with CrowdSec LAPI..."
    local bouncer_key
    bouncer_key=$(cscli bouncers add cs-firewall-bouncer -o raw 2>/dev/null || true)

    if [ -z "$bouncer_key" ]; then
        bouncer_key=$(cscli bouncers add cs-firewall-bouncer --force -o raw 2>/dev/null || true)
    fi

    if [ -z "$bouncer_key" ]; then
        log_error "Failed to generate bouncer API key"
        return 1
    fi

    sed_inplace "s|^api_key:.*$|api_key: ${bouncer_key}|" "$bouncer_config"
    log_info "Bouncer API key configured"
}

enable_alpine_edge_repositories() {
    local edge_base="https://dl-cdn.alpinelinux.org/alpine/edge"
    local repo=""

    for repo in main community testing; do
        local repo_url="${edge_base}/${repo}"
        if ! grep -Fq "$repo_url" /etc/apk/repositories; then
            log_info "Enabling Alpine edge/${repo} repository..."
            printf "%s\n" "$repo_url" >> /etc/apk/repositories
        fi
    done
}

install_apk_with_edge_retry() {
    if $PKG_INSTALL "$@"; then
        return 0
    fi

    log_warn "Package install failed, enabling full Alpine edge repositories and retrying: $*"
    enable_alpine_edge_repositories

    log_info "Updating package lists after enabling edge repositories..."
    $PKG_UPDATE

    $PKG_INSTALL "$@"
}

install_crowdsec() {
    log_info "Installing CrowdSec for intrusion prevention..."

    if command -v cscli >/dev/null 2>&1; then
        log_warn "CrowdSec is already installed, skipping installation"
        return
    fi

    log_info "Updating package lists..."
    $PKG_UPDATE

    log_info "Installing CrowdSec packages..."
    install_apk_with_edge_retry crowdsec crowdsec-openrc

    log_info "Installing CrowdSec firewall bouncer..."
    install_apk_with_edge_retry cs-firewall-bouncer cs-firewall-bouncer-openrc ipset

    sanitize_crowdsec_online_credentials
    ensure_crowdsec_acquisition_datasource

    # Ensure log files exist before CrowdSec starts, otherwise the file
    # acquisition module silently skips missing paths and never re-checks.
    touch /var/log/messages /var/log/auth.log /var/log/secure 2>/dev/null || true

    log_info "Downloading CrowdSec hub index..."
    cscli hub update || log_warn "Failed to update CrowdSec hub index"

    log_info "Registering CrowdSec local machine..."
    cscli machines add -a --force

    log_info "Enabling and starting CrowdSec service..."
    SERVICE_ENABLE crowdsec
    SERVICE_START crowdsec

    log_info "Waiting for CrowdSec LAPI to become ready..."
    wait_for_crowdsec_lapi

    log_info "Ensuring SSH protection collection is installed..."
    cscli collections install crowdsecurity/sshd || log_warn "SSH collection may already be installed"

    log_info "Installing Linux base collection..."
    cscli collections install crowdsecurity/linux || log_warn "Linux collection may already be installed"

    log_info "Reloading CrowdSec with new collections..."
    SERVICE_RELOAD crowdsec
    sleep 3
    wait_for_crowdsec_lapi

    configure_crowdsec_bouncer

    log_info "Starting CrowdSec firewall bouncer..."
    SERVICE_ENABLE cs-firewall-bouncer
    SERVICE_START cs-firewall-bouncer

    log_info "CrowdSec installation completed. Status:"
    cscli metrics || log_warn "Failed to query CrowdSec metrics"

    log_info "CrowdSec is now protecting your server against SSH brute-force and other attacks"
    log_info "You can view alerts with: sudo cscli alerts list"
    log_info "You can view decisions (bans) with: sudo cscli decisions list"
}

enable_bbr() {
    log_info "Checking BBR support..."

    kernel_version=$(uname -r | cut -d. -f1,2)
    kernel_major=$(echo $kernel_version | cut -d. -f1)
    kernel_minor=$(echo $kernel_version | cut -d. -f2)

    if [ "$kernel_major" -lt 4 ] || ([ "$kernel_major" -eq 4 ] && [ "$kernel_minor" -lt 9 ]); then
        log_warn "Kernel version $kernel_version does not support BBR (requires 4.9+)"
        return
    fi

    if ! modinfo tcp_bbr >/dev/null 2>&1; then
        log_warn "BBR module not available in this kernel"
        return
    fi

    log_info "BBR is supported on this system"

    current_congestion=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "")
    if [ "$current_congestion" = "bbr" ]; then
        log_info "BBR is already enabled"
        return
    fi

    log_info "Enabling BBR..."

    modprobe tcp_bbr

    cat >> /etc/sysctl.conf <<EOF

# BBR congestion control
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF

    sysctl -p

    if [ "$(sysctl -n net.ipv4.tcp_congestion_control)" = "bbr" ]; then
        log_info "BBR enabled successfully"
    else
        log_warn "Failed to enable BBR"
    fi
}

restart_ssh() {
    log_info "Restarting SSH service..."
    SERVICE_RESTART sshd || log_warn "Failed to restart SSH service"
    log_info "SSH service restarted"
}

main() {
    log_info "Starting server initialization..."
    echo ""

    parse_arguments "$@"

    detect_os
    apply_cn_proxy_env
    fix_hostname
    report_cn_optimization

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
        configure_nftables
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
        log_info "Firewall has been configured and enabled (nftables)"
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
