#!/bin/bash

# ============================================================================
#                        COMMON LIBRARY FOR VPS SCRIPTS
#                    Shared functions and variables
# ============================================================================

# ============= ENVIRONMENT =============
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# ============= COLORS =============
export RED='\033[0;31m'
export GREEN='\033[0;32m'
export YELLOW='\033[1;33m'
export BLUE='\033[0;34m'
export CYAN='\033[0;36m'
export MAGENTA='\033[0;35m'
export BOLD='\033[1m'
export NC='\033[0m'

# ============= CONFIGURATION =============
export SSH_PORT="4848"
export BACKUP_BASE_DIR="/root/vps-backups"
export LOG_BASE_DIR="/var/log/vps-setup"
export INSTALL_DIR="/opt/vps-config"

# ============= STATE TRACKING =============
# Track installed packages to avoid duplicates
INSTALLED_PACKAGES_FILE="/var/cache/vps-setup/installed-packages.list"
mkdir -p "$(dirname "$INSTALLED_PACKAGES_FILE")"

# ============= LOGGING FUNCTIONS =============
log() {
    local message="$1"
    local log_file="${2:-$LOG_BASE_DIR/setup.log}"
    mkdir -p "$(dirname "$log_file")"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $message" | tee -a "$log_file"
}

log_success() {
    echo -e "${GREEN}✓${NC} $1"
    log "SUCCESS: $1"
}

log_error() {
    echo -e "${RED}✗${NC} $1"
    log "ERROR: $1"
}

log_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
    log "WARNING: $1"
}

log_info() {
    echo -e "${CYAN}ℹ${NC} $1"
    log "INFO: $1"
}

# ============= SYSTEM CHECK FUNCTIONS =============
check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

check_debian() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        if [[ "$ID" != "debian" ]] && [[ "$ID" != "ubuntu" ]]; then
            log_warning "This script is optimized for Debian/Ubuntu"
            return 1
        fi
        return 0
    fi
    return 1
}

get_debian_version() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        echo "$VERSION_ID"
    else
        echo "unknown"
    fi
}

# ============= PACKAGE MANAGEMENT =============
# Smart package installation that tracks what's already installed
install_package() {
    local package="$1"
    local critical="${2:-false}"

    # Check if already processed in this session
    if [ -f "$INSTALLED_PACKAGES_FILE" ] && grep -q "^$package$" "$INSTALLED_PACKAGES_FILE"; then
        log_info "$package already processed in this session"
        return 0
    fi

    # Check if installed on system
    if dpkg -l | grep -q "^ii  $package"; then
        log_success "$package already installed"
        echo "$package" >> "$INSTALLED_PACKAGES_FILE"
        return 0
    fi

    # Install package
    log_info "Installing $package..."
    if DEBIAN_FRONTEND=noninteractive apt-get install -y "$package" -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" &>/dev/null; then
        log_success "$package installed"
        echo "$package" >> "$INSTALLED_PACKAGES_FILE"
        return 0
    else
        if [ "$critical" = "true" ]; then
            log_error "Failed to install critical package: $package"
            return 1
        else
            log_warning "Failed to install $package (non-critical)"
            return 0
        fi
    fi
}

# Batch install packages
install_packages() {
    local -n packages=$1
    local critical="${2:-false}"
    local failed=0

    for pkg in "${packages[@]}"; do
        if ! install_package "$pkg" "$critical"; then
            ((failed++))
        fi
    done

    return $failed
}

# ============= SERVICE MANAGEMENT =============
# Track service states to avoid duplicate operations
SERVICE_STATE_FILE="/var/cache/vps-setup/service-states.list"
mkdir -p "$(dirname "$SERVICE_STATE_FILE")"

manage_service() {
    local service="$1"
    local action="$2"  # start, stop, restart, enable, disable

    # Check if already processed
    local state_key="${service}_${action}"
    if [ -f "$SERVICE_STATE_FILE" ] && grep -q "^$state_key$" "$SERVICE_STATE_FILE"; then
        log_info "Service $service already ${action}ed in this session"
        return 0
    fi

    # Perform action
    if systemctl "$action" "$service" &>/dev/null; then
        log_success "Service $service ${action}ed"
        echo "$state_key" >> "$SERVICE_STATE_FILE"
        return 0
    else
        log_warning "Could not $action service $service"
        return 1
    fi
}

# ============= BACKUP FUNCTIONS =============
create_backup() {
    local source="$1"
    local name="${2:-backup}"

    if [ ! -e "$source" ]; then
        log_warning "Source $source does not exist, skipping backup"
        return 1
    fi

    local timestamp="$(date +%Y%m%d_%H%M%S)"
    local backup_dir="$BACKUP_BASE_DIR/$name/$timestamp"
    mkdir -p "$backup_dir"

    if cp -r "$source" "$backup_dir/"; then
        log_success "Backed up $source to $backup_dir"
        return 0
    else
        log_error "Failed to backup $source"
        return 1
    fi
}

# ============= SSH FUNCTIONS =============
detect_ssh_port() {
    local config_port=$(grep "^Port" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    local running_port=$(ss -tlnp 2>/dev/null | grep sshd | awk '{print $4}' | cut -d':' -f2 | head -n1)

    if [ -n "$config_port" ]; then
        SSH_PORT="$config_port"
        log_info "SSH port detected from config: $SSH_PORT"
    elif [ -n "$running_port" ]; then
        SSH_PORT="$running_port"
        log_info "SSH port detected from running service: $SSH_PORT"
    else
        log_warning "Could not detect SSH port, using default: $SSH_PORT"
    fi

    export SSH_PORT
}

ensure_ssh_port_4848() {
    detect_ssh_port

    if [ "$SSH_PORT" != "4848" ]; then
        log_warning "SSH is not on port 4848 (current: $SSH_PORT)"

        if [ "${AUTO_CONFIGURE:-false}" = "true" ]; then
            create_backup "/etc/ssh/sshd_config" "ssh"
            sed -i 's/^#*Port .*/Port 4848/' /etc/ssh/sshd_config
            log_success "SSH configured for port 4848 (restart required)"
            SSH_PORT="4848"
        fi
    fi
}

# ============= FIREWALL FUNCTIONS =============
find_command() {
    local cmd=$1
    if command -v "$cmd" &> /dev/null; then
        command -v "$cmd"
        return 0
    fi

    for dir in /usr/local/sbin /usr/local/bin /usr/sbin /usr/bin /sbin /bin; do
        if [ -x "$dir/$cmd" ]; then
            echo "$dir/$cmd"
            return 0
        fi
    done

    return 1
}

detect_firewall_backend() {
    local nft_cmd=$(find_command nft)
    local iptables_cmd=$(find_command iptables)

    if [ -n "$nft_cmd" ] && $nft_cmd list tables &>/dev/null; then
        echo "nftables"
    elif [ -n "$iptables_cmd" ]; then
        echo "iptables"
    else
        echo "none"
    fi
}

# ============= NETWORK FUNCTIONS =============
get_public_ip() {
    local ip=$(curl -s -4 ifconfig.me 2>/dev/null || \
               curl -s -4 icanhazip.com 2>/dev/null || \
               curl -s -4 api.ipify.org 2>/dev/null || \
               echo "unknown")
    echo "$ip"
}

test_port() {
    local port="$1"
    local host="${2:-localhost}"

    if timeout 2 bash -c "echo >/dev/tcp/$host/$port" 2>/dev/null; then
        return 0
    else
        return 1
    fi
}

# ============= CLEANUP FUNCTIONS =============
cleanup_session() {
    # Clean up session tracking files
    [ -f "$INSTALLED_PACKAGES_FILE" ] && rm -f "$INSTALLED_PACKAGES_FILE"
    [ -f "$SERVICE_STATE_FILE" ] && rm -f "$SERVICE_STATE_FILE"
}

# ============= ERROR HANDLING =============
set_error_trap() {
    trap 'echo -e "${RED}Error occurred at line $LINENO${NC}"' ERR
    set -e
}

# ============= INIT FUNCTION =============
init_common() {
    # Create necessary directories
    mkdir -p "$LOG_BASE_DIR"
    mkdir -p "$BACKUP_BASE_DIR"
    mkdir -p "$(dirname "$INSTALLED_PACKAGES_FILE")"
    mkdir -p "$(dirname "$SERVICE_STATE_FILE")"

    # Set up error handling
    set_error_trap

    # Check if running as root
    check_root

    # Log initialization
    log "Initialized common library"
}

# Export all functions
export -f log log_success log_error log_warning log_info
export -f check_root check_debian get_debian_version
export -f install_package install_packages manage_service
export -f create_backup detect_ssh_port ensure_ssh_port_4848
export -f find_command detect_firewall_backend
export -f get_public_ip test_port
export -f cleanup_session set_error_trap init_common
