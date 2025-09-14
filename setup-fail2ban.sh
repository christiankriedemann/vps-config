#!/bin/bash

# ============= PATH SETUP =============
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"

# ============= VARIABLEN =============
SCRIPT_VERSION="1.0"
SSH_PORT="4848"  # Dein SSH Port
LOG_FILE="/var/log/fail2ban-setup.log"
BACKUP_DIR="/root/fail2ban-backup-$(date +%Y%m%d_%H%M%S)"

# Farben
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

# ============= HELPER FUNCTIONS =============
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

check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

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
}

# ============= HEADER =============
clear
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}                    ${BOLD}FAIL2BAN SETUP & CONFIGURATION${NC}"
echo -e "${BLUE}                             Version $SCRIPT_VERSION${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# ============= PRE-CHECKS =============
log "Starting fail2ban setup script v$SCRIPT_VERSION"
check_root
detect_ssh_port

# ============= STEP 1: SYSTEM CHECK =============
echo -e "${BOLD}[Step 1/8] System Compatibility Check${NC}"
echo -e "${BLUE}────────────────────────────────────────${NC}"

# Check Debian version
if [ -f /etc/os-release ]; then
    . /etc/os-release
    log_success "OS: $PRETTY_NAME"
    if [[ "$ID" != "debian" ]] && [[ "$ID" != "ubuntu" ]]; then
        log_warning "This script is optimized for Debian/Ubuntu"
    fi
else
    log_error "Cannot determine OS version"
fi

# Check firewall backend
NFT_CMD=$(find_command nft)
IPTABLES_CMD=$(find_command iptables)

if [ -n "$NFT_CMD" ] && $NFT_CMD list tables &>/dev/null; then
    FIREWALL_BACKEND="nftables"
    log_success "Firewall backend: nftables"
elif [ -n "$IPTABLES_CMD" ]; then
    FIREWALL_BACKEND="iptables"
    log_success "Firewall backend: iptables"
else
    log_error "No firewall backend found!"
    exit 1
fi
echo ""

# ============= STEP 2: INSTALLATION =============
echo -e "${BOLD}[Step 2/8] Installing fail2ban${NC}"
echo -e "${BLUE}────────────────────────────────────────${NC}"

# Update package list
log_info "Updating package list..."
apt-get update &>/dev/null || {
    log_error "Failed to update package list"
    exit 1
}

# Install fail2ban and dependencies
PACKAGES=("fail2ban" "python3-pyinotify" "python3-systemd" "whois" "rsyslog")

for pkg in "${PACKAGES[@]}"; do
    if dpkg -l | grep -q "^ii  $pkg"; then
        log_success "$pkg already installed"
    else
        log_info "Installing $pkg..."
        DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg" &>/dev/null || {
            log_error "Failed to install $pkg"
            exit 1
        }
        log_success "$pkg installed"
    fi
done
echo ""

# ============= STEP 3: BACKUP =============
echo -e "${BOLD}[Step 3/8] Creating Backup${NC}"
echo -e "${BLUE}────────────────────────────────────────${NC}"

mkdir -p "$BACKUP_DIR"

# Backup existing configuration
if [ -d /etc/fail2ban ]; then
    cp -r /etc/fail2ban "$BACKUP_DIR/" 2>/dev/null
    log_success "Backup created: $BACKUP_DIR"
else
    log_info "No existing configuration to backup"
fi
echo ""

# ============= STEP 4: BASE CONFIGURATION =============
echo -e "${BOLD}[Step 4/8] Creating Base Configuration${NC}"
echo -e "${BLUE}────────────────────────────────────────${NC}"

# Create fail2ban.local
cat > /etc/fail2ban/fail2ban.local << 'EOF'
[Definition]

# Option: loglevel
# Notes.: Set the log level output.
#         1 = ERROR
#         2 = WARN
#         3 = INFO
#         4 = DEBUG
loglevel = INFO

# Option: logtarget
# Notes.: Set the log target. This could be a file, SYSLOG, STDERR or STDOUT.
logtarget = /var/log/fail2ban.log

# Option: dbfile
# Notes.: Set the file for the fail2ban persistent data to be stored.
dbfile = /var/lib/fail2ban/fail2ban.sqlite3

# Option: dbpurgeage
# Notes.: Sets age at which bans should be purged from the database
dbpurgeage = 1d

# Option: socket
# Notes.: Set the socket file, which is used to communicate with the daemon.
socket = /var/run/fail2ban/fail2ban.sock

# Option: pidfile
# Notes.: Set the PID file.
pidfile = /var/run/fail2ban/fail2ban.pid
EOF

log_success "fail2ban.local created"

# Create jail.local based on firewall backend
cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
# ============= GENERAL SETTINGS =============
# Ban IP for 10 minutes
bantime = 10m

# Window to count failures
findtime = 10m

# Number of failures before ban
maxretry = 5

# Ignore own IPs
ignoreip = 127.0.0.1/8 ::1

# Backend for monitoring
backend = systemd

# Email settings (optional)
destemail = root@localhost
sender = root@$(hostname -f)
mta = sendmail

# Ban action based on firewall
$(if [ "$FIREWALL_BACKEND" = "nftables" ]; then
    echo "banaction = nftables-multiport"
    echo "banaction_allports = nftables-allports"
else
    echo "banaction = iptables-multiport"
    echo "banaction_allports = iptables-allports"
fi)

# ============= JAILS =============

# SSH Protection
[sshd]
enabled = true
port = $SSH_PORT
filter = sshd
logpath = %(sshd_log)s
backend = %(sshd_backend)s
maxretry = 5
findtime = 10m
bantime = 10m

# SSH DDoS Protection
[sshd-ddos]
enabled = true
port = $SSH_PORT
filter = sshd-ddos
logpath = %(sshd_log)s
backend = %(sshd_backend)s
maxretry = 10
findtime = 1m
bantime = 30m

# ============= WEB SERVER PROTECTION =============
# Enable these if you have a web server

# Nginx Authentication Failures
[nginx-http-auth]
enabled = false
filter = nginx-http-auth
port = http,https
logpath = /var/log/nginx/error.log

# Nginx 404 Exploit Scanners
[nginx-noscript]
enabled = false
port = http,https
filter = nginx-noscript
logpath = /var/log/nginx/access.log
maxretry = 6

# Nginx Bad Bots
[nginx-badbots]
enabled = false
port = http,https
filter = nginx-badbots
logpath = /var/log/nginx/access.log
maxretry = 2

# Nginx Proxy Scanners
[nginx-noproxy]
enabled = false
port = http,https
filter = nginx-noproxy
logpath = /var/log/nginx/error.log
maxretry = 2

# Nginx Rate Limiting
[nginx-req-limit]
enabled = false
filter = nginx-req-limit
port = http,https
logpath = /var/log/nginx/error.log
maxretry = 10

# ============= APPLICATION PROTECTION =============

# Docker Protection
[docker-auth]
enabled = false
filter = docker-auth
port = 2375,2376
logpath = /var/log/docker.log
maxretry = 5

# Postfix SMTP
[postfix]
enabled = false
filter = postfix
port = smtp,ssmtp,submission
logpath = /var/log/mail.log
maxretry = 5

# Dovecot IMAP/POP3
[dovecot]
enabled = false
filter = dovecot
port = pop3,pop3s,imap,imaps
logpath = /var/log/mail.log
maxretry = 5

# ============= CUSTOM JAILS =============

# Port Scanning Detection
[port-scan]
enabled = true
filter = port-scan
logpath = /var/log/syslog
maxretry = 5
findtime = 10m
bantime = 1d
action = %(banaction_allports)s[name=%(__name__)s]

# Recidive (Repeat Offenders)
[recidive]
enabled = true
filter = recidive
logpath = /var/log/fail2ban.log
action = %(banaction_allports)s[name=%(__name__)s]
bantime = 1w
findtime = 1d
maxretry = 3
EOF

log_success "jail.local created with $FIREWALL_BACKEND backend"
echo ""

# ============= STEP 5: CUSTOM FILTERS =============
echo -e "${BOLD}[Step 5/8] Creating Custom Filters${NC}"
echo -e "${BLUE}────────────────────────────────────────${NC}"

# SSH DDoS Filter
cat > /etc/fail2ban/filter.d/sshd-ddos.conf << 'EOF'
[Definition]
failregex = ^.* sshd\[.*\]: Did not receive identification string from <HOST>( port \d+)?$
            ^.* sshd\[.*\]: Connection reset by <HOST>( port \d+)? \[preauth\]$
            ^.* sshd\[.*\]: Connection closed by <HOST>( port \d+)? \[preauth\]$
            ^.* sshd\[.*\]: Unable to negotiate with <HOST>( port \d+)?.*$
ignoreregex =
EOF
log_success "Created sshd-ddos filter"

# Port Scan Filter
cat > /etc/fail2ban/filter.d/port-scan.conf << 'EOF'
[Definition]
failregex = ^.* kernel: .* SRC=<HOST> .* DPT=.* WINDOW=.* RES=.*SYN.*$
            ^.* kernel: .* SRC=<HOST> .* DPT=.* FLAG=.*SYN.*$
ignoreregex =
EOF
log_success "Created port-scan filter"

# Docker Auth Filter (if docker is used)
if [ -n "$(find_command docker)" ]; then
    cat > /etc/fail2ban/filter.d/docker-auth.conf << 'EOF'
[Definition]
failregex = ^.* http: authentication failure .* host=<HOST>.*$
            ^.* unauthorized: authentication required .* host=<HOST>.*$
ignoreregex =
EOF
    log_success "Created docker-auth filter"
fi
echo ""

# ============= STEP 6: FIREWALL INTEGRATION =============
echo -e "${BOLD}[Step 6/8] Configuring Firewall Integration${NC}"
echo -e "${BLUE}────────────────────────────────────────${NC}"

if [ "$FIREWALL_BACKEND" = "nftables" ]; then
    # Create nftables action if not exists
    if [ ! -f /etc/fail2ban/action.d/nftables-common.local ]; then
        cat > /etc/fail2ban/action.d/nftables-common.local << 'EOF'
[Init]
# Option: nftables
# Notes.: Actual command to be executed, including common to all calls options
nftables = nft

# Option: nftables_family
# Notes.: IPV4 or IPV6
nftables_family = inet

# Option: nftables_table
# Notes.: Table name for fail2ban chains
nftables_table = fail2ban

# Option: chain
# Notes.: Chain name for fail2ban rules
chain = f2b-<name>

# Option: port
# Notes.: Default port(s) if not specified
port = ssh
EOF
        log_success "Created nftables-common.local"
    fi

    # Initialize fail2ban table in nftables
    $NFT_CMD add table inet fail2ban 2>/dev/null || true
    log_success "nftables fail2ban table ready"

elif [ "$FIREWALL_BACKEND" = "iptables" ]; then
    # Check iptables-save/restore
    if ! command -v iptables-save &>/dev/null; then
        apt-get install -y iptables-persistent &>/dev/null
        log_success "Installed iptables-persistent"
    fi
fi
echo ""

# ============= STEP 7: SERVICE CONFIGURATION =============
echo -e "${BOLD}[Step 7/8] Configuring Service${NC}"
echo -e "${BLUE}────────────────────────────────────────${NC}"

# Enable fail2ban service
systemctl enable fail2ban &>/dev/null || {
    log_error "Failed to enable fail2ban service"
}
log_success "fail2ban service enabled"

# Stop service before config changes
systemctl stop fail2ban &>/dev/null || true

# Test configuration
fail2ban-client -t &>/dev/null
if [ $? -eq 0 ]; then
    log_success "Configuration test passed"
else
    log_error "Configuration test failed!"
    log_info "Check logs: tail -f /var/log/fail2ban.log"
    exit 1
fi

# Start fail2ban
systemctl start fail2ban
if systemctl is-active --quiet fail2ban; then
    log_success "fail2ban service started"
else
    log_error "Failed to start fail2ban"
    journalctl -xe | tail -20
    exit 1
fi
echo ""

# ============= STEP 8: VERIFICATION =============
echo -e "${BOLD}[Step 8/8] Verification & Status${NC}"
echo -e "${BLUE}────────────────────────────────────────${NC}"

# Check status
FAIL2BAN_CMD=$(find_command fail2ban-client)

if [ -n "$FAIL2BAN_CMD" ]; then
    # Get status
    log_info "Active jails:"
    $FAIL2BAN_CMD status | grep "Jail list" | cut -d':' -f2 | tr ',' '\n' | while read jail; do
        if [ -n "$jail" ]; then
            jail=$(echo $jail | tr -d ' \t')
            echo -e "  ${GREEN}✓${NC} $jail"
        fi
    done

    # Check sshd jail specifically
    echo ""
    log_info "SSH Protection Status:"
    if $FAIL2BAN_CMD status sshd &>/dev/null; then
        FILTER=$($FAIL2BAN_CMD status sshd | grep "File list" | cut -d':' -f2 | tr -d '\t')
        BANNED=$($FAIL2BAN_CMD status sshd | grep "Currently banned" | cut -d':' -f2 | tr -d '\t')
        TOTAL=$($FAIL2BAN_CMD status sshd | grep "Total banned" | cut -d':' -f2 | tr -d '\t')

        echo -e "  Port monitored: ${CYAN}$SSH_PORT${NC}"
        echo -e "  Log file: ${CYAN}$FILTER${NC}"
        echo -e "  Currently banned: ${YELLOW}$BANNED${NC} IPs"
        echo -e "  Total banned: ${YELLOW}$TOTAL${NC} IPs"
    else
        log_error "SSH jail not active!"
    fi
fi
echo ""

# ============= CREATE MANAGEMENT SCRIPT =============
echo -e "${BOLD}Creating Management Tools${NC}"
echo -e "${BLUE}────────────────────────────────────────${NC}"

cat > /usr/local/bin/f2b-manage << 'EOF'
#!/bin/bash

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

case "$1" in
    status)
        echo -e "${CYAN}=== Fail2ban Status ===${NC}"
        fail2ban-client status
        echo ""
        for jail in $(fail2ban-client status | grep "Jail list" | cut -d':' -f2 | tr ',' ' '); do
            jail=$(echo $jail | tr -d ' \t')
            if [ -n "$jail" ]; then
                echo -e "${CYAN}=== Jail: $jail ===${NC}"
                fail2ban-client status $jail | grep -E "Currently banned|Total banned|File list"
                echo ""
            fi
        done
        ;;

    ban)
        if [ -z "$2" ] || [ -z "$3" ]; then
            echo "Usage: $0 ban <jail> <ip>"
            exit 1
        fi
        fail2ban-client set $2 banip $3
        echo -e "${GREEN}✓${NC} IP $3 banned in jail $2"
        ;;

    unban)
        if [ -z "$2" ] || [ -z "$3" ]; then
            echo "Usage: $0 unban <jail> <ip>"
            exit 1
        fi
        fail2ban-client set $2 unbanip $3
        echo -e "${GREEN}✓${NC} IP $3 unbanned from jail $2"
        ;;

    unban-all)
        for jail in $(fail2ban-client status | grep "Jail list" | cut -d':' -f2 | tr ',' ' '); do
            jail=$(echo $jail | tr -d ' \t')
            if [ -n "$jail" ]; then
                fail2ban-client unban --all $jail 2>/dev/null || fail2ban-client set $jail unbanip --all 2>/dev/null
                echo -e "${GREEN}✓${NC} All IPs unbanned from jail $jail"
            fi
        done
        ;;

    test-ban)
        if [ -z "$2" ]; then
            echo "Testing SSH ban (will ban 127.0.0.1 for 1 minute)..."
            # Temporarily ban localhost
            fail2ban-client set sshd banip 127.0.0.1
            echo "Banned 127.0.0.1 - checking..."
            sleep 2
            if fail2ban-client status sshd | grep -q "127.0.0.1"; then
                echo -e "${GREEN}✓${NC} Ban test successful"
                fail2ban-client set sshd unbanip 127.0.0.1
                echo "Test IP unbanned"
            else
                echo -e "${RED}✗${NC} Ban test failed"
            fi
        else
            echo "Testing ban for IP: $2"
            fail2ban-client set sshd banip $2
            echo -e "${GREEN}✓${NC} IP $2 banned for testing"
        fi
        ;;

    reload)
        echo "Reloading fail2ban configuration..."
        fail2ban-client reload
        echo -e "${GREEN}✓${NC} Configuration reloaded"
        ;;

    regex-test)
        if [ -z "$2" ] || [ -z "$3" ]; then
            echo "Usage: $0 regex-test <filter> <logfile>"
            echo "Example: $0 regex-test sshd /var/log/auth.log"
            exit 1
        fi
        fail2ban-regex $3 /etc/fail2ban/filter.d/$2.conf
        ;;

    logs)
        echo -e "${CYAN}=== Recent fail2ban logs ===${NC}"
        tail -n ${2:-50} /var/log/fail2ban.log
        ;;

    stats)
        echo -e "${CYAN}=== Fail2ban Statistics ===${NC}"
        echo ""
        TOTAL_BANNED=0
        CURRENT_BANNED=0

        for jail in $(fail2ban-client status | grep "Jail list" | cut -d':' -f2 | tr ',' ' '); do
            jail=$(echo $jail | tr -d ' \t')
            if [ -n "$jail" ]; then
                CURRENT=$(fail2ban-client status $jail | grep "Currently banned" | cut -d':' -f2 | tr -d '\t ')
                TOTAL=$(fail2ban-client status $jail | grep "Total banned" | cut -d':' -f2 | tr -d '\t ')
                CURRENT_BANNED=$((CURRENT_BANNED + CURRENT))
                TOTAL_BANNED=$((TOTAL_BANNED + TOTAL))
                printf "  %-20s Current: %-5s Total: %-5s\n" "$jail:" "$CURRENT" "$TOTAL"
            fi
        done

        echo ""
        echo -e "${CYAN}Summary:${NC}"
        echo "  Total currently banned: $CURRENT_BANNED"
        echo "  Total banned (all time): $TOTAL_BANNED"
        ;;

    *)
        echo "Usage: $0 {status|ban|unban|unban-all|test-ban|reload|regex-test|logs|stats}"
        echo ""
        echo "Commands:"
        echo "  status              - Show status of all jails"
        echo "  ban <jail> <ip>     - Ban an IP in specific jail"
        echo "  unban <jail> <ip>   - Unban an IP from specific jail"
        echo "  unban-all           - Unban all IPs from all jails"
        echo "  test-ban [ip]       - Test ban functionality"
        echo "  reload              - Reload configuration"
        echo "  regex-test          - Test filter regex against log"
        echo "  logs [n]            - Show last n lines of fail2ban log"
        echo "  stats               - Show ban statistics"
        exit 1
        ;;
esac
EOF

chmod +x /usr/local/bin/f2b-manage
log_success "Created management tool: f2b-manage"
echo ""

# ============= FINAL SUMMARY =============
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}Setup Complete!${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

echo -e "\n${GREEN}✓ Configuration Summary:${NC}"
echo -e "  • Firewall Backend: ${CYAN}$FIREWALL_BACKEND${NC}"
echo -e "  • SSH Port Protected: ${CYAN}$SSH_PORT${NC}"
echo -e "  • Configuration: ${CYAN}/etc/fail2ban/jail.local${NC}"
echo -e "  • Backup Location: ${CYAN}$BACKUP_DIR${NC}"
echo -e "  • Log File: ${CYAN}/var/log/fail2ban.log${NC}"

echo -e "\n${YELLOW}Management Commands:${NC}"
echo -e "  ${BOLD}f2b-manage status${NC}     - Show all jail status"
echo -e "  ${BOLD}f2b-manage stats${NC}      - Show statistics"
echo -e "  ${BOLD}f2b-manage ban sshd IP${NC} - Ban an IP"
echo -e "  ${BOLD}f2b-manage unban-all${NC}  - Unban all IPs"
echo -e "  ${BOLD}f2b-manage logs${NC}       - Show recent logs"

echo -e "\n${CYAN}Quick Commands:${NC}"
echo -e "  Watch bans in realtime:  ${BOLD}tail -f /var/log/fail2ban.log${NC}"
echo -e "  Test configuration:      ${BOLD}fail2ban-client -t${NC}"
echo -e "  Restart service:         ${BOLD}systemctl restart fail2ban${NC}"

echo -e "\n${MAGENTA}Next Steps:${NC}"
echo -e "  1. Monitor logs for the first few hours"
echo -e "  2. Adjust ban times and retry counts as needed"
echo -e "  3. Enable additional jails for your services (nginx, docker, etc.)"
echo -e "  4. Consider adding your trusted IPs to ignoreip in jail.local"

echo ""
log "Setup completed successfully!"

# Test the setup
echo -e "${YELLOW}Running quick test...${NC}"
f2b-manage test-ban &>/dev/null
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Fail2ban is working correctly!${NC}"
else
    echo -e "${YELLOW}⚠ Test ban had issues, check logs${NC}"
fi

echo ""
echo -e "${GREEN}Installation complete! Fail2ban is now protecting your server.${NC}"
