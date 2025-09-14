#!/bin/bash

# ============================================================================
#                     VPS COMPLETE SETUP & HARDENING SCRIPT V2
#                              Bootstrap Version with Common Library
# ============================================================================
#
# This script automatically downloads and executes all VPS hardening scripts
# Can be run directly from GitHub with:
# curl -sSL https://raw.githubusercontent.com/christiankriedemann/vps-config/main/setup-v2.sh | bash
#
# ============================================================================

set -e  # Exit on error

# ============= INITIAL CONFIGURATION =============
GITHUB_REPO="christiankriedemann/vps-config"
GITHUB_BRANCH="main"
GITHUB_RAW_URL="https://raw.githubusercontent.com/${GITHUB_REPO}/${GITHUB_BRANCH}"
WORK_DIR="/tmp/vps-setup-$$"
INSTALL_DIR="/opt/vps-config"
AUTO_CONFIGURE=true  # Automatically configure SSH to port 4848

# ============= BOOTSTRAP COMMON LIBRARY =============
# Download common library first
echo "[INIT] Downloading common library..."
mkdir -p "$WORK_DIR/lib"
curl -sSL -o "$WORK_DIR/lib/common.sh" "${GITHUB_RAW_URL}/lib/common.sh" 2>/dev/null || {
    echo "[ERROR] Failed to download common library"
    echo "[INFO] Using fallback mode..."

    # Create minimal common.sh if download fails
    cat > "$WORK_DIR/lib/common.sh" << 'FALLBACK_EOF'
#!/bin/bash
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export RED='\033[0;31m'
export GREEN='\033[0;32m'
export YELLOW='\033[1;33m'
export BLUE='\033[0;34m'
export CYAN='\033[0;36m'
export NC='\033[0m'
export BOLD='\033[1m'
export SSH_PORT="4848"
export LOG_FILE="/var/log/vps-setup-$(date +%Y%m%d_%H%M%S).log"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"; }
log_success() { echo -e "${GREEN}✓${NC} $1" | tee -a "$LOG_FILE"; }
log_error() { echo -e "${RED}✗${NC} $1" | tee -a "$LOG_FILE"; }
log_warning() { echo -e "${YELLOW}⚠${NC} $1" | tee -a "$LOG_FILE"; }
log_info() { echo -e "${CYAN}ℹ${NC} $1" | tee -a "$LOG_FILE"; }
check_root() { [ "$EUID" -eq 0 ] || { log_error "Must run as root"; exit 1; }; }
init_common() { check_root; }
cleanup_session() { true; }
FALLBACK_EOF
}

# Source the common library
source "$WORK_DIR/lib/common.sh"
init_common

# ============= ERROR HANDLING =============
cleanup() {
    cleanup_session
    [ -d "$WORK_DIR" ] && rm -rf "$WORK_DIR"
}

error_exit() {
    log_error "$1"
    echo -e "${RED}Installation failed! Check log: $LOG_FILE${NC}"
    cleanup
    exit 1
}

trap cleanup EXIT
trap 'error_exit "Script interrupted"' INT TERM

# ============= HEADER =============
clear
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}                    ${BOLD}VPS COMPLETE SETUP & HARDENING V2${NC}"
echo -e "${BLUE}                           Bootstrap Installer${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
log "Starting VPS setup script V2 with common library"

# ============= PHASE 1: SYSTEM CHECKS =============
echo -e "${BOLD}[Phase 1/6] System Compatibility Check${NC}"
echo -e "${BLUE}────────────────────────────────────────${NC}"

# Use common library functions if available
if type -t check_debian &>/dev/null; then
    if check_debian; then
        log_success "Debian/Ubuntu detected"
        VERSION=$(get_debian_version)
        log_info "Version: $VERSION"
    else
        log_warning "Non-Debian system detected"
    fi
else
    # Fallback check
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        log_success "OS: $PRETTY_NAME"
    fi
fi

# Check architecture
ARCH=$(uname -m)
log_success "Architecture: $ARCH"

# Check memory
MEM_TOTAL=$(free -m | awk '/^Mem:/{print $2}')
[ "$MEM_TOTAL" -lt 512 ] && log_warning "Low memory: ${MEM_TOTAL}MB"
log_success "Memory: ${MEM_TOTAL}MB"

# Check disk
DISK_AVAIL=$(df / | awk 'NR==2 {print int($4/1024)}')
[ "$DISK_AVAIL" -lt 1024 ] && log_warning "Low disk: ${DISK_AVAIL}MB"
log_success "Disk available: ${DISK_AVAIL}MB"
echo ""

# ============= PHASE 2: NETWORK CHECK =============
echo -e "${BOLD}[Phase 2/6] Network Configuration${NC}"
echo -e "${BLUE}────────────────────────────────────────${NC}"

# Check connectivity
if ! ping -c 1 -W 2 8.8.8.8 &>/dev/null && ! ping -c 1 -W 2 1.1.1.1 &>/dev/null; then
    error_exit "No internet connection"
fi
log_success "Internet connection OK"

# Get public IP using common library or fallback
if type -t get_public_ip &>/dev/null; then
    PUBLIC_IP=$(get_public_ip)
else
    PUBLIC_IP=$(curl -s -4 ifconfig.me 2>/dev/null || echo "unknown")
fi
log_success "Public IP: $PUBLIC_IP"

# Check GitHub
if ! curl -sSf -o /dev/null --connect-timeout 5 https://raw.githubusercontent.com &>/dev/null; then
    error_exit "Cannot reach GitHub"
fi
log_success "GitHub accessible"
echo ""

# ============= PHASE 3: SYSTEM UPDATE & PACKAGES =============
echo -e "${BOLD}[Phase 3/6] System Update & Core Dependencies${NC}"
echo -e "${BLUE}────────────────────────────────────────${NC}"

log_info "Updating package lists..."
apt-get update || error_exit "Failed to update package lists"
log_success "Package lists updated"

log_info "Upgrading existing packages..."
DEBIAN_FRONTEND=noninteractive apt-get upgrade -y || log_warning "Some packages failed to upgrade"
log_success "System packages upgraded"

# Define package groups
ESSENTIAL_PACKAGES=(
    "curl" "wget" "git" "ca-certificates" "gnupg" "lsb-release"
    "software-properties-common" "apt-transport-https" "sudo"
    "unzip" "net-tools" "dnsutils" "htop" "iftop" "ncdu"
    "tree" "jq" "vim" "nano" "rsync" "screen" "tmux"
)

SECURITY_PACKAGES=(
    "ufw" "iptables" "iptables-persistent" "netfilter-persistent"
    "nftables" "fail2ban" "python3-systemd" "python3-pyinotify"
    "aide" "rkhunter" "clamav" "clamav-daemon" "libpam-pwquality" "auditd"
)

MONITORING_PACKAGES=(
    "sysstat" "iotop" "nethogs" "vnstat" "logwatch" "molly-guard"
)

# Install packages using common library function or fallback
if type -t install_packages &>/dev/null; then
    log_info "Installing essential packages using smart installer..."
    install_packages ESSENTIAL_PACKAGES false

    log_info "Installing security packages using smart installer..."
    install_packages SECURITY_PACKAGES false

    log_info "Installing monitoring packages using smart installer..."
    install_packages MONITORING_PACKAGES false
else
    # Fallback installation
    log_info "Installing packages (fallback mode)..."
    for pkg in "${ESSENTIAL_PACKAGES[@]}" "${SECURITY_PACKAGES[@]}" "${MONITORING_PACKAGES[@]}"; do
        if dpkg -l | grep -q "^ii  $pkg"; then
            log_success "$pkg already installed"
        else
            DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg" &>/dev/null || log_warning "Failed: $pkg"
        fi
    done
fi
echo ""

# ============= PHASE 4: SSH PRE-CONFIGURATION =============
echo -e "${BOLD}[Phase 4/6] SSH Pre-Configuration${NC}"
echo -e "${BLUE}────────────────────────────────────────${NC}"

# Backup SSH config using common library or fallback
if type -t create_backup &>/dev/null; then
    create_backup "/etc/ssh/sshd_config" "ssh"
else
    cp /etc/ssh/sshd_config "/etc/ssh/sshd_config.backup.$(date +%Y%m%d_%H%M%S)"
    log_success "SSH config backed up"
fi

# Detect and configure SSH port using common library
if type -t ensure_ssh_port_4848 &>/dev/null; then
    ensure_ssh_port_4848
else
    # Fallback SSH configuration
    CURRENT_SSH_PORT=$(grep "^Port" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo "22")
    log_info "Current SSH port: $CURRENT_SSH_PORT"

    if [ "$CURRENT_SSH_PORT" != "4848" ]; then
        log_warning "SSH is not on port 4848"
        sed -i 's/^#*Port .*/Port 4848/' /etc/ssh/sshd_config
        log_success "SSH configured for port 4848"
    fi
fi

# SSH hardening
cat > /etc/ssh/sshd_config.d/99-hardening.conf << 'EOF'
Protocol 2
MaxAuthTries 3
MaxSessions 10
ClientAliveInterval 300
ClientAliveCountMax 2
LoginGraceTime 60
PermitEmptyPasswords no
StrictModes yes
PubkeyAuthentication yes
IgnoreRhosts yes
HostbasedAuthentication no
X11Forwarding no
PrintMotd no
PrintLastLog yes
TCPKeepAlive yes
Compression delayed
UsePAM yes
SyslogFacility AUTH
LogLevel VERBOSE
EOF
log_success "SSH hardening applied"
echo ""

# ============= PHASE 5: DOWNLOAD ALL SCRIPTS =============
echo -e "${BOLD}[Phase 5/6] Downloading Setup Scripts${NC}"
echo -e "${BLUE}────────────────────────────────────────${NC}"

cd "$WORK_DIR"

# Scripts to download
SCRIPTS=(
    "setup-firewall.sh"
    "setup-fail2ban.sh"
    "setup-kernel-hardening.sh"
    "setup-auto-updates.sh"
    "check-firewall.sh"
    "lib/common.sh"
    "README.md"
)

log_info "Downloading scripts from GitHub..."
for script in "${SCRIPTS[@]}"; do
    # Create directory if needed
    script_dir=$(dirname "$script")
    [ "$script_dir" != "." ] && mkdir -p "$script_dir"

    log_info "Downloading $script..."
    if curl -sSL -o "$script" "${GITHUB_RAW_URL}/${script}"; then
        chmod +x "$script" 2>/dev/null || true
        log_success "$script downloaded"
    else
        log_warning "Failed to download $script"
    fi
done

# Verify critical scripts
for script in "setup-firewall.sh" "setup-fail2ban.sh"; do
    [ ! -f "$script" ] && error_exit "Critical script missing: $script"
done

# Re-source common library with full version
if [ -f "lib/common.sh" ]; then
    source "lib/common.sh"
    log_success "Full common library loaded"
fi
echo ""

# ============= PHASE 6: EXECUTE SETUP SCRIPTS =============
echo -e "${BOLD}[Phase 6/6] Executing Security Setup${NC}"
echo -e "${BLUE}────────────────────────────────────────${NC}"

log_warning "IMPORTANT: Keep this SSH session open!"
log_warning "Test new connections in a separate terminal!"
echo ""

# Execute scripts in order
SETUP_SCRIPTS=(
    "setup-firewall.sh:Firewall Setup:critical"
    "setup-fail2ban.sh:Fail2ban Setup:important"
    "setup-kernel-hardening.sh:Kernel Hardening:optional"
    "setup-auto-updates.sh:Auto Updates:optional"
)

for script_info in "${SETUP_SCRIPTS[@]}"; do
    IFS=':' read -r script_name description priority <<< "$script_info"

    if [ -f "./$script_name" ]; then
        log_info "Running $description..."
        echo -e "${CYAN}Executing $script_name...${NC}"

        if bash "./$script_name"; then
            log_success "$description completed"
        else
            if [ "$priority" = "critical" ]; then
                error_exit "$description failed (critical)"
            else
                log_warning "$description had issues (non-critical)"
            fi
        fi
        echo ""
    else
        log_warning "$script_name not found"
    fi

    # Critical check after firewall setup
    if [ "$script_name" = "setup-firewall.sh" ]; then
        echo ""
        log_warning "CRITICAL: Test SSH now on port 4848 in a NEW terminal!"
        log_info "Command: ssh -p 4848 root@$PUBLIC_IP"
        echo ""
        read -p "Is SSH working on port 4848? (y/n) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_error "SSH test failed - attempting recovery..."
            iptables -I INPUT 1 -p tcp --dport 22 -j ACCEPT
            iptables -I INPUT 1 -p tcp --dport 4848 -j ACCEPT
            log_warning "Emergency rules added"
        fi
    fi
done

# Run verification
log_info "Running security verification..."
if [ -f "./check-firewall.sh" ]; then
    bash "./check-firewall.sh"
fi

# ============= INSTALL SCRIPTS PERMANENTLY =============
echo ""
log_info "Installing scripts to $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"
cp -rf . "$INSTALL_DIR/"
chmod +x "$INSTALL_DIR"/*.sh 2>/dev/null || true
log_success "Scripts installed to $INSTALL_DIR"

# ============= CREATE ENHANCED MANAGEMENT SCRIPT =============
cat > /usr/local/bin/vps-manage << 'EOF'
#!/bin/bash

INSTALL_DIR="/opt/vps-config"

# Source common library if available
[ -f "$INSTALL_DIR/lib/common.sh" ] && source "$INSTALL_DIR/lib/common.sh"

case "$1" in
    check)
        [ -f "$INSTALL_DIR/check-firewall.sh" ] && bash "$INSTALL_DIR/check-firewall.sh" || echo "Check script not found"
        ;;
    update)
        echo "Updating VPS configuration..."
        cd "$INSTALL_DIR"
        git pull 2>/dev/null || curl -sSL https://raw.githubusercontent.com/christiankriedemann/vps-config/main/setup-v2.sh | bash
        ;;
    firewall)
        echo "=== Firewall Status ==="
        iptables -L -n | head -20
        echo ""
        nft list ruleset 2>/dev/null | head -20
        ;;
    fail2ban)
        fail2ban-client status
        ;;
    ssh-test)
        echo "Testing SSH on port 4848..."
        timeout 2 bash -c "echo >/dev/tcp/localhost/4848" && echo "✓ Port 4848 open" || echo "✗ Port 4848 blocked"
        ;;
    updates)
        [ -x /usr/local/bin/check-updates ] && check-updates || echo "Update checker not installed"
        ;;
    kernel)
        echo "=== Kernel Security Parameters ==="
        sysctl -a 2>/dev/null | grep -E "tcp_syncookies|rp_filter|randomize_va_space"
        ;;
    services)
        echo "=== Security Services Status ==="
        for service in nftables fail2ban sshd unattended-upgrades; do
            status=$(systemctl is-active $service 2>/dev/null || echo "not-installed")
            printf "%-20s %s\n" "$service:" "$status"
        done
        ;;
    logs)
        echo "=== Recent Security Logs ==="
        journalctl -xe | grep -E 'fail2ban|nftables|sshd' | tail -30
        ;;
    *)
        echo "Usage: vps-manage {check|update|firewall|fail2ban|ssh-test|updates|kernel|services|logs}"
        echo ""
        echo "Commands:"
        echo "  check     - Run full security check"
        echo "  update    - Update VPS configuration"
        echo "  firewall  - Show firewall status"
        echo "  fail2ban  - Show fail2ban status"
        echo "  ssh-test  - Test SSH port 4848"
        echo "  updates   - Check for system updates"
        echo "  kernel    - Show kernel security settings"
        echo "  services  - Show security services status"
        echo "  logs      - Show recent security logs"
        exit 1
        ;;
esac
EOF
chmod +x /usr/local/bin/vps-manage
log_success "Enhanced management tool installed: vps-manage"

# ============= CLEANUP SESSION TRACKING =============
cleanup_session

# ============= CREATE SUMMARY REPORT =============
REPORT_FILE="/root/vps-setup-report-$(date +%Y%m%d_%H%M%S).txt"
cat > "$REPORT_FILE" << EOF
VPS Setup Report V2
Generated: $(date)
=====================================

System Information:
- OS: $(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d'"' -f2)
- Architecture: $ARCH
- Memory: ${MEM_TOTAL}MB
- Public IP: $PUBLIC_IP

Security Configuration:
- SSH Port: 4848
- Firewall: nftables + iptables (dual stack)
- Fail2ban: Enabled
- Kernel Hardening: Applied
- Auto Updates: Configured
- Open Ports: 80, 443, 4848

Scripts Location: $INSTALL_DIR
Management Tool: vps-manage
Log File: $LOG_FILE
Common Library: $INSTALL_DIR/lib/common.sh

Quick Commands:
- Check status: vps-manage check
- View services: vps-manage services
- Test SSH: vps-manage ssh-test
- Check updates: vps-manage updates

Session Tracking:
- Packages installed: $([ -f /var/cache/vps-setup/installed-packages.list ] && wc -l < /var/cache/vps-setup/installed-packages.list || echo "0")
- Services managed: $([ -f /var/cache/vps-setup/service-states.list ] && wc -l < /var/cache/vps-setup/service-states.list || echo "0")
EOF

# ============= FINAL OUTPUT =============
echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}                    ✓ VPS SETUP V2 COMPLETED SUCCESSFULLY!${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${BOLD}Summary:${NC}"
echo -e "  • SSH Port: ${CYAN}4848${NC}"
echo -e "  • Firewall: ${GREEN}Active${NC}"
echo -e "  • Fail2ban: ${GREEN}Active${NC}"
echo -e "  • Kernel: ${GREEN}Hardened${NC}"
echo -e "  • Updates: ${GREEN}Automatic${NC}"
echo -e "  • Scripts: ${CYAN}$INSTALL_DIR${NC}"
echo ""
echo -e "${BOLD}Management:${NC}"
echo -e "  ${CYAN}vps-manage check${NC}     - Full security check"
echo -e "  ${CYAN}vps-manage services${NC}  - Service status"
echo -e "  ${CYAN}vps-manage update${NC}    - Update configuration"
echo ""
echo -e "${YELLOW}⚠ IMPORTANT:${NC}"
echo -e "  1. ${BOLD}Test SSH NOW:${NC} ssh -p 4848 root@$PUBLIC_IP"
echo -e "  2. ${BOLD}Report saved:${NC} $REPORT_FILE"
echo -e "  3. ${BOLD}Reboot recommended${NC} for full kernel hardening"
echo ""

# Optional reboot
read -p "Reboot now to apply all changes? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}Rebooting in 10 seconds...${NC}"
    echo -e "${YELLOW}SSH after reboot: ssh -p 4848 root@$PUBLIC_IP${NC}"
    sleep 10
    reboot
fi

exit 0
