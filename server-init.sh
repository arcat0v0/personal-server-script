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
# - Configure UFW firewall (SSH, HTTP, HTTPS, Mosh)
# - Install and configure CrowdSec for intrusion prevention
# - Enable BBR if supported
#############################################

set -e

# Global variables
ADDITIONAL_USERS=""
ADD_ADDITIONAL_USERS=false

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
            -h|--help)
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  -a, --add-users         Enable adding additional users (will prompt for details)"
                echo "  -u, --users USERS       Specify additional users (semicolon-separated)"
                echo "                          Format: username@key_url[:sudo|:nopasswd]"
                echo "                          :sudo     - Sudo access (password required)"
                echo "                          :nopasswd - Sudo access (passwordless)"
                echo "  -h, --help              Show this help message"
                echo ""
                echo "Examples:"
                echo "  $0                                    # Run with interactive prompts"
                echo "  $0 -a                                 # Enable additional users, will prompt for details"
                echo "  $0 -u 'alice@url:nopasswd;bob@url:sudo;charlie@url'"
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

            read -p "$(echo -e ${YELLOW}[PROMPT]${NC} Should $username have sudo privileges? \(y/N\): )" -n 1 -r < /dev/tty || local sudo_choice=""
            echo ""
            
            local priv_suffix=""
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                read -p "$(echo -e ${YELLOW}[PROMPT]${NC} Enable passwordless sudo (NOPASSWD) for $username? \(y/N\): )" -n 1 -r < /dev/tty || local nopasswd_choice=""
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

# ... (existing code) ...

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

        if curl -fsSL --connect-timeout 10 --max-time 30 "$key_url" -o "$ssh_dir/authorized_keys"; then
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
    apt-get install -y zsh git curl

    # Check if oh-my-zsh is already installed
    if [ -d "${user_home}/.oh-my-zsh" ]; then
        log_warn "oh-my-zsh is already installed for $username, skipping installation"
    else
        log_info "Installing oh-my-zsh for $username..."
        # Install oh-my-zsh as the user
        su - "$username" -c 'sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" "" --unattended'
    fi

    # Install useful plugins
    log_info "Installing zsh plugins..."

    # zsh-autosuggestions
    if [ -d "${user_home}/.oh-my-zsh/custom/plugins/zsh-autosuggestions" ]; then
        log_warn "zsh-autosuggestions is already installed, skipping"
    else
        su - "$username" -c "git clone https://github.com/zsh-users/zsh-autosuggestions ${user_home}/.oh-my-zsh/custom/plugins/zsh-autosuggestions"
    fi

    # zsh-syntax-highlighting
    if [ -d "${user_home}/.oh-my-zsh/custom/plugins/zsh-syntax-highlighting" ]; then
        log_warn "zsh-syntax-highlighting is already installed, skipping"
    else
        su - "$username" -c "git clone https://github.com/zsh-users/zsh-syntax-highlighting.git ${user_home}/.oh-my-zsh/custom/plugins/zsh-syntax-highlighting"
    fi

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

    log_info "Mosh installed successfully"
}

# Configure UFW firewall
configure_ufw() {
    log_info "Configuring UFW firewall..."

    # Install ufw if not present
    if ! command -v ufw &>/dev/null; then
        log_info "Installing UFW..."
        apt-get install -y ufw
    fi

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
    curl -s https://install.crowdsec.net | sh
    
    # Update package lists to ensure the new repository is recognized
    log_info "Updating package lists..."
    apt-get update -y

    # Install CrowdSec
    log_info "Installing CrowdSec..."
    apt-get install -y crowdsec

    # Install firewall bouncer
    log_info "Installing CrowdSec firewall bouncer..."
    apt-get install -y crowdsec-firewall-bouncer-iptables

    # Enable and start CrowdSec service
    log_info "Enabling CrowdSec service..."
    systemctl enable crowdsec
    systemctl start crowdsec

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
    systemctl reload crowdsec

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
    systemctl restart sshd || systemctl restart ssh
    log_info "SSH service restarted"
}

# Main execution
main() {
    log_info "Starting server initialization..."
    echo ""

    # Parse command line arguments
    parse_arguments "$@"

    detect_os
    fix_hostname

    # Prompt for additional users if not specified via command line
    prompt_additional_users

    update_system
    create_user
    import_ssh_keys
    create_additional_users
    disable_root_login
    install_zsh
    install_direnv
    install_mosh
    configure_ufw
    install_crowdsec
    enable_bbr
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
    log_info "Zsh with oh-my-zsh has been installed"
    log_info "Starship prompt has been configured with plain-text-symbols preset"
    log_info "Direnv has been installed and configured"
    log_info "Mosh has been installed for better remote connections"
    log_info "UFW firewall has been configured and enabled"
    log_info "CrowdSec has been installed for intrusion prevention"
    log_info "BBR has been checked and enabled if supported"
    log_info ""
    log_warn "IMPORTANT: Please test SSH login with user 'arcat' before closing this session!"
    log_info "You can also connect using: mosh arcat@your-server-ip"
    log_info ""
    log_info "CrowdSec commands:"
    log_info "  - View alerts: sudo cscli alerts list"
    log_info "  - View bans: sudo cscli decisions list"
    log_info "  - View metrics: sudo cscli metrics"
    log_info "=========================================="
}

main "$@"
