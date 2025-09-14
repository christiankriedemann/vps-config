#!/bin/bash

# ============================================================================
#                    AUTOMATIC SECURITY UPDATES CONFIGURATION
#                           For Debian/Ubuntu Systems
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
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# ============= INSTALL REQUIRED PACKAGES =============
log_info "Installing required packages..."

PACKAGES=(
    "unattended-upgrades"
    "apt-listchanges"
    "apt-config-auto-update"
    "powermgmt-base"
    "python3-apt"
    "update-notifier-common"
    "needrestart"
    "debian-goodies"
)

for pkg in "${PACKAGES[@]}"; do
    if dpkg -l | grep -q "^ii  $pkg"; then
        log_success "$pkg already installed"
    else
        apt-get install -y "$pkg" &>/dev/null || log_warning "Could not install $pkg"
    fi
done

# ============= CONFIGURE UNATTENDED-UPGRADES =============
echo ""
log_info "Configuring unattended-upgrades..."

# Backup existing configuration
if [ -f /etc/apt/apt.conf.d/50unattended-upgrades ]; then
    cp /etc/apt/apt.conf.d/50unattended-upgrades "/etc/apt/apt.conf.d/50unattended-upgrades.backup.$(date +%Y%m%d_%H%M%S)"
fi

# Create main configuration
cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
// Automatically upgrade packages from these origins
Unattended-Upgrade::Origins-Pattern {
    // Debian systems
    "origin=Debian,codename=${distro_codename},label=Debian";
    "origin=Debian,codename=${distro_codename},label=Debian-Security";
    "origin=Debian,codename=${distro_codename}-security,label=Debian-Security";
    "origin=Debian,codename=${distro_codename}-updates";

    // Ubuntu systems
    "origin=Ubuntu,archive=${distro_codename}-security,label=Ubuntu";
    "origin=Ubuntu,archive=${distro_codename}-updates,label=Ubuntu";

    // Extended security maintenance
    "origin=UbuntuESMApps,archive=${distro_codename}-apps-security";
    "origin=UbuntuESM,archive=${distro_codename}-infra-security";
};

// Package blacklist - packages that should never be automatically upgraded
Unattended-Upgrade::Package-Blacklist {
    // Example: "linux-generic";
    // Add critical packages here that might break your system
};

// Remove unused kernel packages automatically
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";

// Remove unused dependencies automatically
Unattended-Upgrade::Remove-Unused-Dependencies "true";

// Remove new unused dependencies automatically
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";

// Automatically reboot if required (at specified time)
Unattended-Upgrade::Automatic-Reboot "true";

// Reboot time (2:00 AM)
Unattended-Upgrade::Automatic-Reboot-Time "02:00";

// Only reboot if no users are logged in
Unattended-Upgrade::Automatic-Reboot-WithUsers "false";

// Send email notifications
Unattended-Upgrade::Mail "root";

// Only send mail on errors
Unattended-Upgrade::MailReport "only-on-error";

// Detailed logging
Unattended-Upgrade::SyslogEnable "true";
Unattended-Upgrade::SyslogFacility "daemon";

// Speed up downloads
Unattended-Upgrade::MinimalSteps "true";

// Bandwidth limit in kb/s (0 = unlimited)
Acquire::http::Dl-Limit "0";

// Split upgrade into smallest possible chunks
Unattended-Upgrade::MinimalSteps "true";

// Install updates on shutdown
Unattended-Upgrade::InstallOnShutdown "false";

// Debug level (0-3)
Unattended-Upgrade::Debug "1";

// Development release upgrades (not recommended for production)
Unattended-Upgrade::DevRelease "false";

// Allow downgrading packages if necessary
Unattended-Upgrade::Allow-downgrade "false";
EOF

log_success "Configured unattended-upgrades"

# ============= CONFIGURE AUTO-UPDATE =============
log_info "Configuring automatic update checks..."

cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
// Enable automatic updates
APT::Periodic::Enable "1";

// Update package lists daily
APT::Periodic::Update-Package-Lists "1";

// Download upgradeable packages daily
APT::Periodic::Download-Upgradeable-Packages "1";

// Run unattended-upgrades daily
APT::Periodic::Unattended-Upgrade "1";

// AutocleanInterval (in days)
APT::Periodic::AutocleanInterval "7";

// Remove obsolete packages every 7 days
APT::Periodic::CleanInterval "7";

// Check for updates when on battery
Unattended-Upgrade::OnlyOnACPower "false";
EOF

log_success "Configured automatic update checks"

# ============= CONFIGURE NEEDRESTART =============
echo ""
log_info "Configuring automatic service restarts..."

cat > /etc/needrestart/conf.d/99-autorestart.conf << 'EOF'
# Automatically restart services after library upgrades
$nrconf{restart} = 'a';

# Automatically restart kernel if needed
$nrconf{kernelhints} = 1;

# Skip interactive mode
$nrconf{ui} = 'NeedRestart::UI::stdio';

# Exclude some services from automatic restart
$nrconf{override}->{qr(^docker)} = 0;
$nrconf{override}->{qr(^containerd)} = 0;
$nrconf{override}->{qr(^ssh)} = 0;
EOF

log_success "Configured needrestart for automatic service restarts"

# ============= CREATE UPDATE NOTIFICATION SCRIPT =============
echo ""
log_info "Creating update notification script..."

cat > /usr/local/bin/check-updates << 'EOF'
#!/bin/bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}=== System Update Status ===${NC}"
echo ""

# Check for available updates
apt-get update &>/dev/null
UPDATES=$(apt list --upgradable 2>/dev/null | grep -c upgradable || echo "0")
SECURITY=$(apt list --upgradable 2>/dev/null | grep -c security || echo "0")

if [ "$UPDATES" -gt 1 ]; then
    echo -e "${YELLOW}⚠ $((UPDATES-1)) updates available${NC}"
    echo -e "${YELLOW}  Including $SECURITY security updates${NC}"
    echo ""
    echo "Recent updates:"
    apt list --upgradable 2>/dev/null | head -10
else
    echo -e "${GREEN}✓ System is up to date${NC}"
fi

# Check if reboot is required
if [ -f /var/run/reboot-required ]; then
    echo ""
    echo -e "${RED}⚠ System reboot required!${NC}"
    if [ -f /var/run/reboot-required.pkgs ]; then
        echo "Packages requiring reboot:"
        cat /var/run/reboot-required.pkgs
    fi
fi

# Check last update time
echo ""
echo -e "${CYAN}Last updates:${NC}"
grep "unattended-upgrades" /var/log/dpkg.log 2>/dev/null | tail -5 || echo "No recent automatic updates"

# Check needrestart
if command -v needrestart &>/dev/null; then
    echo ""
    echo -e "${CYAN}Services needing restart:${NC}"
    needrestart -b -l 2>/dev/null | grep -E "^NEEDRESTART-SVC" | cut -d: -f2 || echo "None"
fi
EOF

chmod +x /usr/local/bin/check-updates
log_success "Created update check script: check-updates"

# ============= CREATE SYSTEMD TIMER FOR NOTIFICATIONS =============
echo ""
log_info "Creating systemd timer for update notifications..."

cat > /etc/systemd/system/update-notification.service << 'EOF'
[Unit]
Description=Check for system updates and send notification
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/update-notification.sh
EOF

cat > /etc/systemd/system/update-notification.timer << 'EOF'
[Unit]
Description=Daily update notification check
Requires=update-notification.service

[Timer]
OnCalendar=daily
OnBootSec=10min
Persistent=true

[Install]
WantedBy=timers.target
EOF

cat > /usr/local/bin/update-notification.sh << 'EOF'
#!/bin/bash

# Check for updates
apt-get update &>/dev/null
UPDATES=$(apt list --upgradable 2>/dev/null | grep -c upgradable || echo "0")

# Log update status
logger -t update-check "System has $((UPDATES-1)) updates available"

# Check for reboot
if [ -f /var/run/reboot-required ]; then
    logger -t update-check "System reboot required"

    # Send notification to all logged-in users
    wall "System reboot required after recent updates. Please schedule a reboot."
fi

# Create status file for MOTD
mkdir -p /var/cache/update-status
echo "Updates available: $((UPDATES-1))" > /var/cache/update-status/current
date > /var/cache/update-status/last-check
EOF

chmod +x /usr/local/bin/update-notification.sh

systemctl daemon-reload
systemctl enable update-notification.timer
systemctl start update-notification.timer

log_success "Created update notification timer"

# ============= CONFIGURE MOTD =============
echo ""
log_info "Configuring MOTD for update notifications..."

cat > /etc/update-motd.d/95-updates << 'EOF'
#!/bin/bash

if [ -f /var/cache/update-status/current ]; then
    UPDATES=$(cat /var/cache/update-status/current | cut -d: -f2)
    if [ "$UPDATES" -gt 0 ]; then
        echo ""
        echo "  System Updates: $UPDATES packages available"
        echo "  Run 'check-updates' for details"
    fi
fi

if [ -f /var/run/reboot-required ]; then
    echo ""
    echo "  *** System restart required ***"
fi
EOF

chmod +x /etc/update-motd.d/95-updates
log_success "Configured MOTD notifications"

# ============= ENABLE SERVICES =============
echo ""
log_info "Enabling automatic update services..."

# Enable unattended-upgrades
systemctl enable unattended-upgrades
systemctl start unattended-upgrades
log_success "Enabled unattended-upgrades service"

# Enable apt daily timers
systemctl enable apt-daily.timer
systemctl enable apt-daily-upgrade.timer
systemctl start apt-daily.timer
systemctl start apt-daily-upgrade.timer
log_success "Enabled APT daily timers"

# ============= TEST CONFIGURATION =============
echo ""
log_info "Testing configuration..."

# Dry run test
unattended-upgrade --debug --dry-run 2>&1 | head -20
log_success "Configuration test completed"

# ============= CREATE MANAGEMENT SCRIPT =============
cat > /usr/local/bin/update-manage << 'EOF'
#!/bin/bash

case "$1" in
    status)
        echo "=== Automatic Updates Status ==="
        systemctl status unattended-upgrades --no-pager | head -15
        echo ""
        echo "=== Timers ==="
        systemctl list-timers apt-daily* update-notification* --all
        ;;

    check)
        /usr/local/bin/check-updates
        ;;

    logs)
        echo "=== Recent Automatic Updates ==="
        grep unattended-upgrade /var/log/apt/history.log | tail -20
        ;;

    test)
        echo "Running dry-run test..."
        unattended-upgrade --debug --dry-run
        ;;

    force)
        echo "Forcing immediate update check..."
        unattended-upgrade --debug
        ;;

    disable)
        systemctl stop unattended-upgrades
        systemctl disable unattended-upgrades
        echo "Automatic updates disabled"
        ;;

    enable)
        systemctl enable unattended-upgrades
        systemctl start unattended-upgrades
        echo "Automatic updates enabled"
        ;;

    *)
        echo "Usage: update-manage {status|check|logs|test|force|disable|enable}"
        exit 1
        ;;
esac
EOF

chmod +x /usr/local/bin/update-manage
log_success "Created management script: update-manage"

# ============= SUMMARY =============
echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}              ✓ AUTOMATIC UPDATES CONFIGURED SUCCESSFULLY${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${BOLD}Configuration Summary:${NC}"
echo -e "  • Security Updates: ${GREEN}Automatic${NC}"
echo -e "  • Update Schedule: ${CYAN}Daily${NC}"
echo -e "  • Automatic Reboot: ${CYAN}2:00 AM (if needed)${NC}"
echo -e "  • Service Restart: ${GREEN}Automatic${NC}"
echo -e "  • Email Reports: ${CYAN}On errors only${NC}"
echo ""
echo -e "${BOLD}Management Commands:${NC}"
echo -e "  ${CYAN}check-updates${NC}       - Check for available updates"
echo -e "  ${CYAN}update-manage status${NC} - Show service status"
echo -e "  ${CYAN}update-manage logs${NC}   - View update history"
echo -e "  ${CYAN}update-manage test${NC}   - Run dry-run test"
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
