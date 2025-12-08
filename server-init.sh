#!/bin/bash

#############################################
# Server Initialization Script
# Supports: Debian, Ubuntu
# Features:
# - Disable root login
# - Create sudo user 'arcat'
# - Import SSH keys from GitHub
# - Update system
# - Install and configure zsh with oh-my-zsh
# - Install and configure starship prompt
# - Install and configure direnv
# - Install mosh for better remote connections
# - Enable BBR if supported
#############################################

set -e

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

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   log_error "This script must be run as root"
   exit 1
fi

# Detect OS
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        VERSION=$VERSION_ID
    else
        log_error "Cannot detect OS"
        exit 1
    fi

    if [[ "$OS" != "debian" && "$OS" != "ubuntu" ]]; then
        log_error "This script only supports Debian and Ubuntu"
        exit 1
    fi

    log_info "Detected OS: $OS $VERSION"
}

# Update system
update_system() {
    log_info "Updating system packages..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get upgrade -y
    apt-get dist-upgrade -y
    apt-get autoremove -y
    apt-get autoclean -y
    log_info "System updated successfully"
}

# Create user arcat
create_user() {
    local username="arcat"

    if id "$username" &>/dev/null; then
        log_warn "User $username already exists, skipping creation"
    else
        log_info "Creating user $username..."
        useradd -m -s /bin/bash "$username"
        log_info "User $username created"
    fi

    # Add to sudo group
    log_info "Adding $username to sudo group..."
    usermod -aG sudo "$username"

    # Configure passwordless sudo
    log_info "Configuring passwordless sudo for $username..."
    echo "$username ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/$username
    chmod 0440 /etc/sudoers.d/$username
    log_info "Passwordless sudo configured"
}

# Detect if in China network
is_china_network() {
    # Try to detect China network by checking common indicators
    # Method 1: Check if can reach GitHub quickly
    if curl -s --connect-timeout 3 --max-time 5 https://github.com > /dev/null 2>&1; then
        return 1  # Not in China or GitHub is accessible
    fi

    # Method 2: Check timezone
    local timezone=$(timedatectl 2>/dev/null | grep "Time zone" | awk '{print $3}')
    if [[ "$timezone" == "Asia/Shanghai" ]] || [[ "$timezone" == "Asia/Chongqing" ]] || [[ "$timezone" == "Asia/Urumqi" ]]; then
        return 0  # Likely in China
    fi

    # Method 3: Check if common China DNS servers are reachable
    if ping -c 1 -W 1 114.114.114.114 > /dev/null 2>&1 || ping -c 1 -W 1 223.5.5.5 > /dev/null 2>&1; then
        return 0  # Likely in China
    fi

    return 1  # Default to not in China
}

# Import SSH keys from GitHub
import_ssh_keys() {
    local username="arcat"
    local github_user="arcat0v0"
    local ssh_dir="/home/$username/.ssh"
    local github_url="https://github.com/${github_user}.keys"
    local cf_worker_url="https://arcat_keys.xvx.rs"

    log_info "Importing SSH keys from GitHub..."

    # Create .ssh directory if not exists
    mkdir -p "$ssh_dir"

    # Detect network and choose appropriate URL
    local keys_url="$github_url"
    if is_china_network; then
        log_info "Detected China network, using Cloudflare Worker proxy..."
        keys_url="$cf_worker_url"
    fi

    # Try primary URL
    log_info "Downloading keys from: $keys_url"
    if curl -fsSL --connect-timeout 10 --max-time 30 "$keys_url" -o "$ssh_dir/authorized_keys"; then
        log_info "SSH keys downloaded successfully"
    else
        log_warn "Failed to download from primary source, trying fallback..."

        # Try fallback URL
        if [ "$keys_url" = "$github_url" ]; then
            # If GitHub failed, try Cloudflare Worker
            log_info "Trying Cloudflare Worker proxy..."
            if curl -fsSL --connect-timeout 10 --max-time 30 "$cf_worker_url" -o "$ssh_dir/authorized_keys"; then
                log_info "SSH keys downloaded successfully via Cloudflare Worker"
            else
                log_error "Failed to download SSH keys from all sources"
                exit 1
            fi
        else
            # If Cloudflare Worker failed, try GitHub
            log_info "Trying GitHub directly..."
            if curl -fsSL --connect-timeout 10 --max-time 30 "$github_url" -o "$ssh_dir/authorized_keys"; then
                log_info "SSH keys downloaded successfully from GitHub"
            else
                log_error "Failed to download SSH keys from all sources"
                exit 1
            fi
        fi
    fi

    # Verify keys file is not empty
    if [ ! -s "$ssh_dir/authorized_keys" ]; then
        log_error "Downloaded keys file is empty"
        exit 1
    fi

    # Set correct permissions
    chmod 700 "$ssh_dir"
    chmod 600 "$ssh_dir/authorized_keys"
    chown -R "$username:$username" "$ssh_dir"

    log_info "SSH keys imported and permissions set"
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
    apt-get install -y zsh git curl

    log_info "Installing oh-my-zsh for $username..."

    # Install oh-my-zsh as the user
    su - "$username" -c 'sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" "" --unattended'

    # Install useful plugins
    log_info "Installing zsh plugins..."

    # zsh-autosuggestions
    su - "$username" -c "git clone https://github.com/zsh-users/zsh-autosuggestions ${user_home}/.oh-my-zsh/custom/plugins/zsh-autosuggestions"

    # zsh-syntax-highlighting
    su - "$username" -c "git clone https://github.com/zsh-users/zsh-syntax-highlighting.git ${user_home}/.oh-my-zsh/custom/plugins/zsh-syntax-highlighting"

    # Configure .zshrc with recommended plugins
    log_info "Configuring zsh plugins..."
    su - "$username" -c "sed -i 's/^plugins=(git)/plugins=(git sudo zsh-autosuggestions zsh-syntax-highlighting colored-man-pages command-not-found)/' ${user_home}/.zshrc"

    # Install and configure starship
    log_info "Installing starship prompt..."
    curl -sS https://starship.rs/install.sh | sh -s -- -y

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
    apt-get install -y direnv

    # Add direnv hook to .zshrc
    log_info "Configuring direnv for zsh..."
    su - "$username" -c "echo 'eval \"\$(direnv hook zsh)\"' >> ${user_home}/.zshrc"

    log_info "Direnv installed successfully"
}

# Install mosh
install_mosh() {
    log_info "Installing mosh..."

    apt-get install -y mosh

    # Open mosh ports in firewall if ufw is active
    if command -v ufw &>/dev/null && ufw status | grep -q "Status: active"; then
        log_info "Configuring firewall for mosh..."
        ufw allow 60000:61000/udp
        log_info "Firewall rules added for mosh (UDP ports 60000-61000)"
    fi

    log_info "Mosh installed successfully"
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
    systemctl restart sshd || systemctl restart ssh
    log_info "SSH service restarted"
}

# Main execution
main() {
    log_info "Starting server initialization..."
    echo ""

    detect_os
    update_system
    create_user
    import_ssh_keys
    disable_root_login
    install_zsh
    install_direnv
    install_mosh
    enable_bbr
    restart_ssh

    echo ""
    log_info "=========================================="
    log_info "Server initialization completed!"
    log_info "=========================================="
    log_info "User 'arcat' has been created with sudo privileges"
    log_info "SSH keys imported from GitHub"
    log_info "Root login has been disabled"
    log_info "Zsh with oh-my-zsh has been installed"
    log_info "Starship prompt has been configured with plain-text-symbols preset"
    log_info "Direnv has been installed and configured"
    log_info "Mosh has been installed for better remote connections"
    log_info "BBR has been checked and enabled if supported"
    log_info ""
    log_warn "IMPORTANT: Please test SSH login with user 'arcat' before closing this session!"
    log_info "You can also connect using: mosh arcat@your-server-ip"
    log_info "=========================================="
}

main "$@"
