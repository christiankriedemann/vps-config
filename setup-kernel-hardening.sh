#!/bin/bash

# ============================================================================
#                        KERNEL SECURITY HARDENING SCRIPT
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
echo -e "${BLUE}                       ${BOLD}KERNEL SECURITY HARDENING${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Backup existing sysctl configuration
BACKUP_FILE="/etc/sysctl.conf.backup.$(date +%Y%m%d_%H%M%S)"
cp /etc/sysctl.conf "$BACKUP_FILE"
log_success "Backed up sysctl.conf to $BACKUP_FILE"

# Create custom sysctl configuration
cat > /etc/sysctl.d/99-security-hardening.conf << 'EOF'
# ============================================================================
#                     KERNEL SECURITY HARDENING PARAMETERS
# ============================================================================

# ============= NETWORK SECURITY =============

# IP Spoofing protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0

# Ignore send redirects
net.ipv4.conf.all.send_redirects = 0

# Disable source packet routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# Log Martians (packets with impossible addresses)
net.ipv4.conf.all.log_martians = 1

# Ignore ICMP ping requests (optional - uncomment to enable)
#net.ipv4.icmp_echo_ignore_all = 1

# Ignore ICMP broadcasts
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Ignore ICMP errors
net.ipv4.icmp_ignore_bogus_error_responses = 1

# ============= SYN FLOOD PROTECTION =============

# SYN cookies (protection against SYN flood attacks)
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_max_syn_backlog = 4096

# ============= TCP/IP STACK HARDENING =============

# TCP timestamps (can help prevent wrapped sequence number attacks)
net.ipv4.tcp_timestamps = 1

# TCP FIN timeout
net.ipv4.tcp_fin_timeout = 20

# TCP keepalive parameters
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15

# Increase TCP buffer sizes for better performance
net.core.rmem_default = 31457280
net.core.rmem_max = 33554432
net.core.wmem_default = 31457280
net.core.wmem_max = 33554432
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_rmem = 4096 87380 33554432
net.ipv4.tcp_wmem = 4096 65536 33554432

# ============= IPv6 SECURITY =============

# Disable IPv6 if not needed (uncomment to disable)
#net.ipv6.conf.all.disable_ipv6 = 1
#net.ipv6.conf.default.disable_ipv6 = 1
#net.ipv6.conf.lo.disable_ipv6 = 1

# IPv6 Privacy Extensions
net.ipv6.conf.all.use_tempaddr = 2
net.ipv6.conf.default.use_tempaddr = 2

# ============= KERNEL SECURITY =============

# Kernel panic reboot timeout
kernel.panic = 60

# Restrict kernel logs to root only
kernel.dmesg_restrict = 1

# Restrict kernel pointers in proc
kernel.kptr_restrict = 2

# Ptrace scope restriction
kernel.yama.ptrace_scope = 1

# Disable SysRq key
kernel.sysrq = 0

# Core dumps restriction
fs.suid_dumpable = 0

# PID max value
kernel.pid_max = 65536

# Address Space Layout Randomization
kernel.randomize_va_space = 2

# ============= FILE SYSTEM SECURITY =============

# Protected hardlinks and symlinks
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_regular = 2
fs.protected_fifos = 2

# File descriptor limits
fs.file-max = 2097152

# ============= SHARED MEMORY SECURITY =============

# Destroy shared memory segments not in use
kernel.shm_rmid_forced = 1

# Shared memory max size
kernel.shmmax = 68719476736
kernel.shmall = 4294967296

# ============= CONNECTION TRACKING =============

# Connection tracking table size
net.netfilter.nf_conntrack_max = 524288
net.nf_conntrack_max = 524288

# Connection tracking timeouts
net.netfilter.nf_conntrack_tcp_timeout_established = 1800
net.netfilter.nf_conntrack_tcp_timeout_close = 10
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 10
net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 20
net.netfilter.nf_conntrack_tcp_timeout_last_ack = 20
net.netfilter.nf_conntrack_tcp_timeout_syn_recv = 20
net.netfilter.nf_conntrack_tcp_timeout_syn_sent = 20
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 10

# ============= PERFORMANCE TUNING =============

# Swappiness (lower = less swap usage)
vm.swappiness = 10

# Cache pressure
vm.vfs_cache_pressure = 50

# Dirty ratio
vm.dirty_ratio = 10
vm.dirty_background_ratio = 5

# ============= DOCKER COMPATIBILITY =============
# These settings ensure Docker continues to work properly

# IP forwarding (required for Docker)
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1

# Bridge netfilter (required for Docker)
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-arptables = 1

# ============================================================================
EOF

log_success "Created /etc/sysctl.d/99-security-hardening.conf"

# Apply sysctl settings
echo ""
log_info "Applying kernel parameters..."
sysctl -p /etc/sysctl.d/99-security-hardening.conf 2>/dev/null | head -20
log_success "Kernel parameters applied"

# ============= ADDITIONAL KERNEL MODULES BLACKLIST =============
echo ""
log_info "Creating kernel module blacklist..."

cat > /etc/modprobe.d/security-blacklist.conf << 'EOF'
# Disable rare network protocols
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true

# Disable rare filesystems
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install udf /bin/true
install vfat /bin/true

# Disable USB storage (uncomment if needed)
#install usb-storage /bin/true

# Disable Bluetooth (uncomment if not needed)
#install bluetooth /bin/true
#install btusb /bin/true

# Disable Firewire
install firewire-core /bin/true
install firewire-ohci /bin/true
install firewire-sbp2 /bin/true

# Disable thunderbolt
install thunderbolt /bin/true
EOF

log_success "Created kernel module blacklist"

# ============= GRUB HARDENING =============
echo ""
log_info "Hardening GRUB bootloader..."

if [ -f /etc/default/grub ]; then
    cp /etc/default/grub "/etc/default/grub.backup.$(date +%Y%m%d_%H%M%S)"

    # Add security parameters to GRUB
    if ! grep -q "slab_nomerge" /etc/default/grub; then
        sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="/GRUB_CMDLINE_LINUX_DEFAULT="slab_nomerge slub_debug=FZP page_poison=1 pti=on /' /etc/default/grub
        log_success "Added kernel boot parameters for security"
    fi

    # Update GRUB
    if command -v update-grub &>/dev/null; then
        update-grub 2>/dev/null
        log_success "GRUB configuration updated"
    fi
else
    log_warning "GRUB config not found - skipping bootloader hardening"
fi

# ============= COREDUMP RESTRICTION =============
echo ""
log_info "Restricting core dumps..."

cat > /etc/security/limits.d/99-disable-coredumps.conf << 'EOF'
# Disable core dumps for all users
* soft core 0
* hard core 0
EOF

cat > /etc/systemd/coredump.conf.d/disable.conf << 'EOF'
[Coredump]
Storage=none
ProcessSizeMax=0
EOF

log_success "Core dumps restricted"

# ============= NETWORK PARAMETERS PERSISTENCE =============
echo ""
log_info "Ensuring network parameters persist..."

cat > /etc/systemd/system/kernel-hardening.service << 'EOF'
[Unit]
Description=Apply Kernel Security Hardening Parameters
After=network.target

[Service]
Type=oneshot
ExecStart=/sbin/sysctl -p /etc/sysctl.d/99-security-hardening.conf
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable kernel-hardening.service
log_success "Created persistence service"

# ============= VERIFICATION =============
echo ""
echo -e "${BOLD}Verification:${NC}"
echo -e "${BLUE}────────────────────────────────────────${NC}"

# Check important parameters
check_param() {
    local param=$1
    local expected=$2
    local current=$(sysctl -n $param 2>/dev/null)

    if [ "$current" = "$expected" ]; then
        echo -e "  ${GREEN}✓${NC} $param = $current"
    else
        echo -e "  ${YELLOW}⚠${NC} $param = $current (expected: $expected)"
    fi
}

check_param "net.ipv4.tcp_syncookies" "1"
check_param "net.ipv4.conf.all.rp_filter" "1"
check_param "net.ipv4.conf.all.accept_redirects" "0"
check_param "kernel.randomize_va_space" "2"
check_param "fs.protected_symlinks" "1"

# ============= SUMMARY =============
echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}                    ✓ KERNEL HARDENING COMPLETED${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${BOLD}Applied Security Features:${NC}"
echo -e "  • SYN Flood Protection: ${GREEN}Enabled${NC}"
echo -e "  • IP Spoofing Protection: ${GREEN}Enabled${NC}"
echo -e "  • ICMP Redirect Protection: ${GREEN}Enabled${NC}"
echo -e "  • Kernel Pointer Restriction: ${GREEN}Enabled${NC}"
echo -e "  • ASLR: ${GREEN}Enabled${NC}"
echo -e "  • Core Dump Restriction: ${GREEN}Enabled${NC}"
echo -e "  • Symlink/Hardlink Protection: ${GREEN}Enabled${NC}"
echo ""
echo -e "${CYAN}Configuration Files:${NC}"
echo -e "  • /etc/sysctl.d/99-security-hardening.conf"
echo -e "  • /etc/modprobe.d/security-blacklist.conf"
echo -e "  • /etc/security/limits.d/99-disable-coredumps.conf"
echo ""
echo -e "${YELLOW}Note:${NC} Some changes require a reboot to take full effect"
echo ""

exit 0
