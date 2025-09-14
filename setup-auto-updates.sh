#!/bin/bash

# ============================================================================
#                    AUTOMATIC SECURITY UPDATES CONFIGURATION
#                           For Debian Systems Only
# ============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Logging
log_success() { echo -e "${GREEN}✓${NC} $1"; }
log_error() { echo -e "${RED}✗${NC} $1"; }
log_warning() { echo -e "${YELLOW}⚠${NC} $1"; }
log_info() { echo -e "${CYAN}ℹ${NC} $1"; }

# Check root
if [ "$EUID" -ne 0 ]; then
    log_error "This script must be run as root"
    exit 1
fi

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}                    ${BOLD}AUTOMATIC SECURITY UPDATES SETUP${NC}"
echo -e "${BLUE}                             Debian Edition${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# ============= INSTALL REQUIRED PACKAGES =============
log_info "Installing required packages for Debian..."

PACKAGES=(
    "unattended-upgrades"
    "apt-listchanges"
    "python3-apt"
    "needrestart"
    "debian-goodies"
)

for pkg in "${PACKAGES[@]}"; do
    if dpkg -l | grep -q "^ii  $pkg"; then
        log_success "$pkg already installed"
    else
        apt-get install -y "$pkg" || log_warning "Could not install $pkg"
    fi
done

# ============= CONFIGURE UNATTENDED-UPGRADES =============
echo ""
log_info "Configuring unattended-upgrades for Debian..."

# Backup existing configuration
if [ -f /etc/apt/apt.conf.d/50unattended-upgrades ]; then
    cp /etc/apt/apt.conf.d/50unattended-upgrades "/etc/apt/apt.conf.d/50unattended-upgrades.backup.$(date +%Y%m%d_%H%M%S)"
fi

# Create Debian-specific configuration
cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
// Automatic upgrades configuration for Debian
Unattended-Upgrade::Origins-Pattern {
    // Debian security and stable updates
    "origin=Debian,codename=${distro_codename},label=Debian";
    "origin=Debian,codename=${distro_codename},label=Debian-Security";
    "origin=Debian,codename=${distro_codename}-security,label=Debian-Security";
    "origin=Debian,codename=${distro_codename}-updates";
    "origin=Debian,codename=${distro_codename}-proposed-updates";
};

// Package blacklist
Unattended-Upgrade::Package-Blacklist {
    // Kernel updates (uncomment to prevent automatic kernel updates)
    // "linux-image-*";
    // "linux-headers-*";
};

// Automatic removal of unused packages
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";

// Automatic reboot settings
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "02:00";
Unattended-Upgrade::Automatic-Reboot-WithUsers "false";

// Email configuration
Unattended-Upgrade::Mail "root";
Unattended-Upgrade::MailReport "only-on-error";

// Logging
Unattended-Upgrade::SyslogEnable "true";
Unattended-Upgrade::SyslogFacility "daemon";

// Performance
Unattended-Upgrade::MinimalSteps "true";
Acquire::http::Dl-Limit "0";

// Debug (0=none, 3=maximum)
Unattended-Upgrade::Debug "1";

// Don't upgrade to development releases
Unattended-Upgrade::DevRelease "false";
EOF

log_success "Configured unattended-upgrades for Debian"

# ============= CONFIGURE AUTO-UPDATE =============
log_info "Configuring automatic update checks..."

cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
// Enable automatic updates for Debian
APT::Periodic::Enable "1";
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::CleanInterval "7";
EOF

log_success "Configured automatic update checks"

# ============= CONFIGURE NEEDRESTART =============
echo ""
log_info "Configuring automatic service restarts..."

mkdir -p /etc/needrestart/conf.d/
cat > /etc/needrestart/conf.d/99-autorestart.conf << 'EOF'
# Automatically restart services after library upgrades
$nrconf{restart} = 'a';

# Automatically check kernel
$nrconf{kernelhints} = 1;

# Non-interactive mode
$nrconf{ui} = 'NeedRestart::UI::stdio';

# Don't restart these services automatically
$nrconf{override}->{qr(^docker)} = 0;
$nrconf{override}->{qr(^containerd)} = 0;
$nrconf{override}->{qr(^ssh)} = 0;
EOF

log_success "Configured needrestart"

# ============= CREATE CHECK SCRIPT =============
echo ""
log_info "Creating update check script..."

cat > /usr/local/bin/check-updates << 'EOF'
#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}=== Debian System Update Status ===${NC}"
echo ""

# Update package lists
apt-get update &>/dev/null

# Check for updates
UPDATES=$(apt list --upgradable 2>/dev/null | grep -c upgradable || echo "0")
SECURITY=$(apt list --upgradable 2>/dev/null | grep -c -E 'Debian-Security|security' || echo "0")

if [ "$UPDATES" -gt 1 ]; then
    echo -e "${YELLOW}⚠ $((UPDATES-1)) updates available${NC}"
    echo -e "${YELLOW}  Including $SECURITY security updates${NC}"
    echo ""
    echo "Available updates:"
    apt list --upgradable 2>/dev/null | head -10
else
    echo -e "${GREEN}✓ System is up to date${NC}"
fi

# Check if reboot required
if [ -f /var/run/reboot-required ]; then
    echo ""
    echo -e "${RED}⚠ System reboot required!${NC}"
    if [ -f /var/run/reboot-required.pkgs ]; then
        echo "Packages requiring reboot:"
        cat /var/run/reboot-required.pkgs
    fi
fi

# Check needrestart
if command -v needrestart &>/dev/null; then
    echo ""
    echo -e "${CYAN}Services needing restart:${NC}"
    needrestart -b -l 2>/dev/null | grep -E "^NEEDRESTART-SVC" | cut -d: -f2 || echo "None"
fi

# Show last unattended-upgrades run
echo ""
echo -e "${CYAN}Last automatic update:${NC}"
grep "unattended-upgrades" /var/log/dpkg.log 2>/dev/null | tail -1 || echo "No recent automatic updates"
EOF

chmod +x /usr/local/bin/check-updates
log_success "Created update check script"

# ============= ENABLE SERVICES =============
echo ""
log_info "Enabling automatic update services..."

# Enable and start services
systemctl enable unattended-upgrades || log_warning "Could not enable unattended-upgrades"
systemctl start unattended-upgrades || log_warning "Could not start unattended-upgrades"

# Enable APT timers
systemctl enable apt-daily.timer || log_warning "Could not enable apt-daily timer"
systemctl enable apt-daily-upgrade.timer || log_warning "Could not enable apt-daily-upgrade timer"
systemctl start apt-daily.timer
systemctl start apt-daily-upgrade.timer

log_success "Automatic update services enabled"

# ============= TEST CONFIGURATION =============
echo ""
log_info "Testing configuration..."

# Dry run test (nur die ersten 10 Zeilen für bessere Übersicht)
unattended-upgrade --debug --dry-run 2>&1 | head -10 || log_warning "Dry run had warnings"
log_success "Configuration test completed"

# ============= SUMMARY =============
echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}              ✓ AUTOMATIC UPDATES CONFIGURED FOR DEBIAN${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${BOLD}Configuration:${NC}"
echo -e "  • Security Updates: ${GREEN}Automatic${NC}"
echo -e "  • Update Schedule: ${CYAN}Daily${NC}"
echo -e "  • Reboot Time: ${CYAN}2:00 AM${NC} (if needed)"
echo -e "  • Service Restart: ${GREEN}Automatic${NC}"
echo ""
echo -e "${BOLD}Commands:${NC}"
echo -e "  ${CYAN}check-updates${NC}              - Check for available updates"
echo -e "  ${CYAN}unattended-upgrade${NC}         - Run updates manually"
echo -e "  ${CYAN}needrestart${NC}                - Check services needing restart"
echo ""
echo -e "${BOLD}Configuration Files:${NC}"
echo -e "  • /etc/apt/apt.conf.d/50unattended-upgrades"
echo -e "  • /etc/apt/apt.conf.d/20auto-upgrades"
echo -e "  • /etc/needrestart/conf.d/99-autorestart.conf"
echo ""
echo -e "${YELLOW}Note:${NC} System will automatically install security updates daily"
echo -e "      and reboot at 2:00 AM if required (when no users logged in)"
echo ""

exit 0
