#!/bin/bash

# ============================================================================
#                     VPS COMPLETE SETUP & HARDENING SCRIPT
#                              Bootstrap Version
# ============================================================================
#
# This script automatically downloads and executes all VPS hardening scripts
# Can be run directly from GitHub with:
# curl -sSL https://raw.githubusercontent.com/christiankriedemann/vps-config/main/setup.sh | bash
#
# ============================================================================

set -e  # Exit on error

# ============= CONFIGURATION =============
GITHUB_REPO="christiankriedemann/vps-config"
GITHUB_BRANCH="main"
GITHUB_RAW_URL="https://raw.githubusercontent.com/${GITHUB_REPO}/${GITHUB_BRANCH}"
WORK_DIR="/tmp/vps-setup-$$"
INSTALL_DIR="/opt/vps-config"
LOG_FILE="/var/log/vps-setup-$(date +%Y%m%d_%H%M%S).log"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m'

# ============= LOGGING =============
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log_success() {
    echo -e "${GREEN}✓${NC} $1" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "${RED}✗${NC} $1" | tee -a "$LOG_FILE"
}

log_warning() {
    echo -e "${YELLOW}⚠${NC} $1" | tee -a "$LOG_FILE"
}

log_info() {
    echo -e "${CYAN}ℹ${NC} $1" | tee -a "$LOG_FILE"
}

# ============= ERROR HANDLING =============
cleanup() {
    if [ -d "$WORK_DIR" ]; then
        rm -rf "$WORK_DIR"
    fi
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
echo -e "${BLUE}                    ${BOLD}VPS COMPLETE SETUP & HARDENING${NC}"
echo -e "${BLUE}                           Bootstrap Installer${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
log "Starting VPS setup script"

# ============= ROOT CHECK =============
if [ "$EUID" -ne 0 ]; then
    error_exit "This script must be run as root"
fi
log_success "Running as root"

# ============= OS CHECK =============
echo -e "${BOLD}[Phase 1/6] System Compatibility Check${NC}"
echo -e "${BLUE}────────────────────────────────────────${NC}"

if [ -f /etc/os-release ]; then
    . /etc/os-release
    log_success "OS: $PRETTY_NAME"

    if [[ "$ID" != "debian" ]] && [[ "$ID" != "ubuntu" ]]; then
        log_warning "This script is optimized for Debian/Ubuntu"
        read -p "Continue anyway? (y/n) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            error_exit "Installation cancelled by user"
        fi
    fi

    # Check Debian version
    if [[ "$ID" == "debian" ]]; then
        if [[ "$VERSION_ID" != "11" && "$VERSION_ID" != "12" && "$VERSION_ID" != "13" ]]; then
            log_warning "This script is tested on Debian 11/12/13"
            log_info "You are running Debian $VERSION_ID"
        fi
    fi
else
    error_exit "Cannot determine OS version"
fi

# Check architecture
ARCH=$(uname -m)
if [[ "$ARCH" != "x86_64" ]] && [[ "$ARCH" != "aarch64" ]]; then
    log_warning "Untested architecture: $ARCH"
fi
log_success "Architecture: $ARCH"

# Check available memory
MEM_TOTAL=$(free -m | awk '/^Mem:/{print $2}')
if [ "$MEM_TOTAL" -lt 512 ]; then
    log_warning "Low memory detected: ${MEM_TOTAL}MB (recommended: 512MB+)"
fi
log_success "Memory: ${MEM_TOTAL}MB"

# Check disk space
DISK_AVAIL=$(df / | awk 'NR==2 {print int($4/1024)}')
if [ "$DISK_AVAIL" -lt 1024 ]; then
    log_warning "Low disk space: ${DISK_AVAIL}MB (recommended: 1GB+)"
fi
log_success "Available disk: ${DISK_AVAIL}MB"
echo ""

# ============= NETWORK CHECK =============
echo -e "${BOLD}[Phase 2/6] Network Configuration${NC}"
echo -e "${BLUE}────────────────────────────────────────${NC}"

# Check internet connectivity
log_info "Checking internet connectivity..."
if ! ping -c 1 -W 2 8.8.8.8 &>/dev/null && ! ping -c 1 -W 2 1.1.1.1 &>/dev/null; then
    error_exit "No internet connection detected"
fi
log_success "Internet connection OK"

# Get public IP
PUBLIC_IP=$(curl -s -4 ifconfig.me 2>/dev/null || curl -s -4 icanhazip.com 2>/dev/null || echo "unknown")
log_success "Public IP: $PUBLIC_IP"

# Check if GitHub is accessible
if ! curl -sSf -o /dev/null --connect-timeout 5 https://raw.githubusercontent.com &>/dev/null; then
    error_exit "Cannot reach GitHub"
fi
log_success "GitHub accessible"
echo ""

# ============= SYSTEM UPDATE =============
echo -e "${BOLD}[Phase 3/6] System Update & Core Dependencies${NC}"
echo -e "${BLUE}────────────────────────────────────────${NC}"

log_info "Updating package lists..."
apt-get update || error_exit "Failed to update package lists"
log_success "Package lists updated"

log_info "Upgrading existing packages (this may take a while)..."
DEBIAN_FRONTEND=noninteractive apt-get upgrade -y || log_warning "Some packages failed to upgrade"
log_success "System packages upgraded"

# Install essential packages first
log_info "Installing essential packages..."
ESSENTIAL_PACKAGES=(
    "curl"
    "wget"
    "git"
    "ca-certificates"
    "gnupg"
    "lsb-release"
    "software-properties-common"
    "apt-transport-https"
    "sudo"
    "unzip"
    "net-tools"
    "dnsutils"
    "htop"
    "iftop"
    "ncdu"
    "tree"
    "jq"
    "vim"
    "nano"
    "rsync"
    "screen"
    "tmux"
)

for pkg in "${ESSENTIAL_PACKAGES[@]}"; do
    if dpkg -l | grep -q "^ii  $pkg"; then
        log_success "$pkg already installed"
    else
        log_info "Installing $pkg..."
        DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg" &>/dev/null || log_warning "Failed to install $pkg"
    fi
done

# Install security packages
log_info "Installing security packages..."
SECURITY_PACKAGES=(
    "ufw"
    "iptables"
    "iptables-persistent"
    "netfilter-persistent"
    "nftables"
    "fail2ban"
    "python3-systemd"
    "python3-pyinotify"
    "aide"
    "rkhunter"
    "clamav"
    "clamav-daemon"
    "libpam-pwquality"
    "auditd"
)

for pkg in "${SECURITY_PACKAGES[@]}"; do
    if dpkg -l | grep -q "^ii  $pkg"; then
        log_success "$pkg already installed"
    else
        log_info "Installing $pkg..."
        DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg" &>/dev/null || log_warning "Failed to install $pkg (non-critical)"
    fi
done

# Install monitoring packages
log_info "Installing monitoring packages..."
MONITORING_PACKAGES=(
    "sysstat"
    "iotop"
    "nethogs"
    "vnstat"
    "monit"
    "logwatch"
    "molly-guard"  # Prevents accidental shutdowns
)

for pkg in "${MONITORING_PACKAGES[@]}"; do
    if dpkg -l | grep -q "^ii  $pkg"; then
        log_success "$pkg already installed"
    else
        log_info "Installing $pkg..."
        DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg" &>/dev/null || log_warning "Failed to install $pkg (optional)"
    fi
done
echo ""

# ============= SSH HARDENING =============
echo -e "${BOLD}[Phase 4/6] SSH Pre-Configuration${NC}"
echo -e "${BLUE}────────────────────────────────────────${NC}"

# Backup SSH config
if [ -f /etc/ssh/sshd_config ]; then
    cp /etc/ssh/sshd_config "/etc/ssh/sshd_config.backup.$(date +%Y%m%d_%H%M%S)"
    log_success "SSH config backed up"
fi

# Check current SSH port
CURRENT_SSH_PORT=$(grep "^Port" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo "22")
log_info "Current SSH port: $CURRENT_SSH_PORT"

if [ "$CURRENT_SSH_PORT" != "4848" ]; then
    log_warning "SSH is not on port 4848"
    echo -e "${YELLOW}The setup will configure SSH on port 4848${NC}"
    echo -e "${YELLOW}Make sure you can access port 4848 after setup!${NC}"
    read -p "Continue? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        error_exit "Installation cancelled - SSH port change required"
    fi
fi

# Apply basic SSH hardening
log_info "Applying SSH hardening..."
cat >> /etc/ssh/sshd_config.d/99-hardening.conf << 'EOF'
# Security hardening
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

# Logging
SyslogFacility AUTH
LogLevel VERBOSE
EOF
log_success "SSH hardening applied"
echo ""

# ============= DOWNLOAD SCRIPTS =============
echo -e "${BOLD}[Phase 5/6] Downloading Setup Scripts${NC}"
echo -e "${BLUE}────────────────────────────────────────${NC}"

# Create working directory
mkdir -p "$WORK_DIR"
cd "$WORK_DIR"

# List of scripts to download
SCRIPTS=(
    "setup-firewall.sh"
    "setup-fail2ban.sh"
    "setup-kernel-hardening.sh"
    "setup-auto-updates.sh"
    "check-firewall.sh"
    "check-scurity.sh"
    "README.md"
)

log_info "Downloading scripts from GitHub..."
for script in "${SCRIPTS[@]}"; do
    log_info "Downloading $script..."
    if curl -sSL -o "$script" "${GITHUB_RAW_URL}/${script}"; then
        chmod +x "$script" 2>/dev/null || true
        log_success "$script downloaded"
    else
        log_warning "Failed to download $script"
    fi
done

# Verify critical scripts exist
for script in "setup-firewall.sh" "setup-fail2ban.sh"; do
    if [ ! -f "$script" ]; then
        error_exit "Critical script missing: $script"
    fi
done
echo ""

# ============= EXECUTE SETUP SCRIPTS =============
echo -e "${BOLD}[Phase 6/6] Executing Security Setup${NC}"
echo -e "${BLUE}────────────────────────────────────────${NC}"

# Save current SSH session info
log_warning "IMPORTANT: Keep this SSH session open!"
log_warning "Test new connections in a separate terminal!"
echo ""

# Step 1: Firewall Setup
log_info "Setting up firewall..."
echo -e "${CYAN}Running setup-firewall.sh...${NC}"
if bash ./setup-firewall.sh; then
    log_success "Firewall setup completed"
else
    error_exit "Firewall setup failed"
fi

# Wait and test
echo ""
log_warning "CRITICAL: Test SSH now on port 4848 in a NEW terminal!"
log_info "Command: ssh -p 4848 root@$PUBLIC_IP"
echo ""
read -p "Is SSH working on port 4848? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    log_error "SSH test failed - attempting recovery..."
    # Emergency recovery
    iptables -I INPUT 1 -p tcp --dport 22 -j ACCEPT
    iptables -I INPUT 1 -p tcp --dport 4848 -j ACCEPT
    log_warning "Emergency rules added - try again"
    read -p "Is SSH working now? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        error_exit "Cannot confirm SSH access - aborting for safety"
    fi
fi

# Step 2: Fail2ban Setup
log_info "Setting up fail2ban..."
echo -e "${CYAN}Running setup-fail2ban.sh...${NC}"
if bash ./setup-fail2ban.sh; then
    log_success "Fail2ban setup completed"
else
    log_warning "Fail2ban setup had issues (non-critical)"
fi

# Step 3: Kernel Hardening
log_info "Applying kernel security hardening..."
echo -e "${CYAN}Running setup-kernel-hardening.sh...${NC}"
if [ -f ./setup-kernel-hardening.sh ]; then
    if bash ./setup-kernel-hardening.sh; then
        log_success "Kernel hardening completed"
    else
        log_warning "Kernel hardening had issues (non-critical)"
    fi
else
    log_warning "Kernel hardening script not found"
fi

# Step 4: Automatic Updates
log_info "Configuring automatic security updates..."
echo -e "${CYAN}Running setup-auto-updates.sh...${NC}"
if [ -f ./setup-auto-updates.sh ]; then
    if bash ./setup-auto-updates.sh; then
        log_success "Automatic updates configured"
    else
        log_warning "Automatic updates setup had issues (non-critical)"
    fi
else
    log_warning "Auto-updates script not found"
fi

# Step 5: Verification
echo ""
log_info "Running security verification..."
echo -e "${CYAN}Running check-firewall.sh...${NC}"
if [ -f ./check-firewall.sh ]; then
    bash ./check-firewall.sh
else
    log_warning "Check script not available"
fi

# ============= INSTALL SCRIPTS PERMANENTLY =============
echo ""
log_info "Installing scripts to $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"
cp -f *.sh "$INSTALL_DIR/" 2>/dev/null || true
cp -f README.md "$INSTALL_DIR/" 2>/dev/null || true
chmod +x "$INSTALL_DIR"/*.sh 2>/dev/null || true
log_success "Scripts installed to $INSTALL_DIR"

# ============= CREATE MANAGEMENT SCRIPT =============
cat > /usr/local/bin/vps-manage << 'EOF'
#!/bin/bash

INSTALL_DIR="/opt/vps-config"

case "$1" in
    check)
        if [ -f "$INSTALL_DIR/check-firewall.sh" ]; then
            bash "$INSTALL_DIR/check-firewall.sh"
        else
            echo "Check script not found"
        fi
        ;;
    update)
        echo "Updating VPS configuration scripts..."
        cd "$INSTALL_DIR"
        # Add your GitHub repo URL here
        git pull || echo "Not a git repository"
        ;;
    firewall)
        echo "Firewall status:"
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
    *)
        echo "Usage: vps-manage {check|update|firewall|fail2ban|ssh-test}"
        exit 1
        ;;
esac
EOF
chmod +x /usr/local/bin/vps-manage
log_success "Management tool installed: vps-manage"

# ============= FINAL CLEANUP =============
echo ""
log_info "Cleaning up..."
apt-get autoremove -y &>/dev/null || true
apt-get autoclean -y &>/dev/null || true
cleanup

# ============= CREATE SUMMARY REPORT =============
REPORT_FILE="/root/vps-setup-report-$(date +%Y%m%d_%H%M%S).txt"
cat > "$REPORT_FILE" << EOF
VPS Setup Report
Generated: $(date)
=====================================

System Information:
- OS: $PRETTY_NAME
- Architecture: $ARCH
- Memory: ${MEM_TOTAL}MB
- Public IP: $PUBLIC_IP

Security Configuration:
- SSH Port: 4848
- Firewall: nftables + iptables (dual stack)
- Fail2ban: Enabled
- Open Ports: 22, 80, 443, 4848

Installed Components:
$(dpkg -l | grep -E "nftables|iptables|fail2ban|ufw" | awk '{print "- " $2 " " $3}')

Scripts Location: $INSTALL_DIR
Management Tool: vps-manage
Log File: $LOG_FILE

Next Steps:
1. Test SSH: ssh -p 4848 root@$PUBLIC_IP
2. Check status: vps-manage check
3. Review fail2ban: fail2ban-client status
4. Monitor logs: tail -f /var/log/fail2ban.log

Important Files:
- /etc/nftables.conf
- /etc/fail2ban/jail.local
- /etc/ssh/sshd_config
- $INSTALL_DIR/

Emergency Commands:
- Reset firewall: iptables -F && iptables -P INPUT ACCEPT
- Unban IP: fail2ban-client unban <IP>
- Check ports: ss -tlnp
EOF

# ============= FINAL OUTPUT =============
echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}                    ✓ VPS SETUP COMPLETED SUCCESSFULLY!${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${BOLD}Summary:${NC}"
echo -e "  • SSH Port: ${CYAN}4848${NC}"
echo -e "  • Firewall: ${GREEN}Active${NC}"
echo -e "  • Fail2ban: ${GREEN}Active${NC}"
echo -e "  • Scripts: ${CYAN}$INSTALL_DIR${NC}"
echo -e "  • Report: ${CYAN}$REPORT_FILE${NC}"
echo ""
echo -e "${BOLD}Quick Commands:${NC}"
echo -e "  ${CYAN}vps-manage check${NC}    - Check security status"
echo -e "  ${CYAN}f2b-manage status${NC}   - Fail2ban status"
echo -e "  ${CYAN}vps-manage firewall${NC} - Firewall rules"
echo ""
echo -e "${YELLOW}⚠ IMPORTANT:${NC}"
echo -e "  1. ${BOLD}Test SSH NOW:${NC} ssh -p 4848 root@$PUBLIC_IP"
echo -e "  2. ${BOLD}Save this info${NC} before closing this session"
echo -e "  3. ${BOLD}Reboot recommended${NC} to ensure persistence"
echo ""
echo -e "${GREEN}Setup log saved to: $LOG_FILE${NC}"
echo -e "${GREEN}Report saved to: $REPORT_FILE${NC}"
echo ""

# ============= OPTIONAL REBOOT =============
read -p "Do you want to reboot now to test persistence? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}Rebooting in 10 seconds...${NC}"
    echo -e "${YELLOW}SSH after reboot: ssh -p 4848 root@$PUBLIC_IP${NC}"
    sleep 10
    reboot
fi

exit 0
