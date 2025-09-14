#!/bin/bash

# ============= PATH SETUP =============
# Stelle sicher, dass alle Standard-Debian-Pfade im PATH sind
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# Farben für Output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Exit on error
set -e

# Trap für Fehlerbehandlung
trap 'echo -e "${RED}Error occurred at line $LINENO${NC}"' ERR

echo -e "${BLUE}================================================${NC}"
echo -e "${BLUE}   Unified Firewall Setup for Debian 12/13    ${NC}"
echo -e "${BLUE}================================================${NC}"
echo ""
echo -e "${GREEN}PATH configured: $PATH${NC}"
echo ""

# ============= SCHRITT 1: System-Checks =============
echo -e "${YELLOW}[1/11] Running system compatibility checks...${NC}"

# Check ob wir als root laufen
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}✗ This script must be run as root${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Running as root${NC}"

# Check Debian Version
if [ -f /etc/os-release ]; then
    . /etc/os-release
    if [[ "$ID" == "debian" && ("$VERSION_ID" == "12" || "$VERSION_ID" == "13") ]]; then
        echo -e "${GREEN}✓ Debian $VERSION_ID detected${NC}"
    else
        echo -e "${YELLOW}⚠ Warning: This script is designed for Debian 12/13${NC}"
        echo -e "  Detected: $NAME $VERSION_ID"
        read -p "Continue anyway? (y/n) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
else
    echo -e "${RED}✗ Cannot determine OS version${NC}"
    exit 1
fi

# ============= SCHRITT 2: Package Installation =============
echo ""
echo -e "${YELLOW}[2/11] Installing required packages...${NC}"

# Update package list
echo -e "${BLUE}Updating package list...${NC}"
apt update || {
    echo -e "${RED}✗ Failed to update package list${NC}"
    exit 1
}

# Liste der benötigten Pakete
PACKAGES=(
    "nftables"
    "iptables"
    "netfilter-persistent"
    "iptables-persistent"
    "net-tools"
    "fail2ban"
)

# Installiere Pakete
for pkg in "${PACKAGES[@]}"; do
    if dpkg -l | grep -q "^ii  $pkg"; then
        echo -e "${GREEN}✓ $pkg already installed${NC}"
    else
        echo -e "${BLUE}Installing $pkg...${NC}"
        DEBIAN_FRONTEND=noninteractive apt install -y "$pkg" || {
            echo -e "${RED}✗ Failed to install $pkg${NC}"
            # Bei nftables versuche Neuinstallation
            if [ "$pkg" = "nftables" ]; then
                echo -e "${YELLOW}Attempting reinstall of nftables...${NC}"
                apt-get remove --purge -y nftables 2>/dev/null || true
                apt-get install -y nftables
            else
                exit 1
            fi
        }
        echo -e "${GREEN}✓ $pkg installed${NC}"
    fi
done

# ============= SCHRITT 3: Verify Installation =============
echo ""
echo -e "${YELLOW}[3/11] Verifying installations...${NC}"

# Check nftables - versuche verschiedene Methoden
NFT_CMD=""
if command -v nft &> /dev/null; then
    NFT_CMD=$(command -v nft)
    echo -e "${GREEN}✓ nft found at: $NFT_CMD${NC}"
elif [ -x "/usr/sbin/nft" ]; then
    NFT_CMD="/usr/sbin/nft"
    echo -e "${GREEN}✓ nft found at: $NFT_CMD${NC}"
elif [ -x "/sbin/nft" ]; then
    NFT_CMD="/sbin/nft"
    echo -e "${GREEN}✓ nft found at: $NFT_CMD${NC}"
else
    echo -e "${RED}✗ nft command not found${NC}"
    echo -e "${YELLOW}Attempting to locate nft...${NC}"
    NFT_LOCATION=$(find /usr -name nft -type f 2>/dev/null | head -1)
    if [ -n "$NFT_LOCATION" ] && [ -x "$NFT_LOCATION" ]; then
        NFT_CMD="$NFT_LOCATION"
        echo -e "${GREEN}✓ Found nft at: $NFT_CMD${NC}"
    else
        echo -e "${RED}✗ Cannot find nft binary. Reinstalling...${NC}"
        apt-get remove --purge -y nftables
        apt-get install -y nftables
        # Try again
        if command -v nft &> /dev/null; then
            NFT_CMD=$(command -v nft)
        elif [ -x "/usr/sbin/nft" ]; then
            NFT_CMD="/usr/sbin/nft"
        else
            echo -e "${RED}✗ Failed to install nftables properly${NC}"
            exit 1
        fi
    fi
fi

# Zeige Version
NFT_VERSION=$($NFT_CMD --version 2>/dev/null | head -n1) || NFT_VERSION="unknown"
echo -e "${GREEN}✓ nftables version: $NFT_VERSION${NC}"

# Check iptables
if command -v iptables &> /dev/null; then
    echo -e "${GREEN}✓ iptables installed${NC}"
else
    echo -e "${RED}✗ iptables not found${NC}"
    exit 1
fi

# Check fail2ban
if command -v fail2ban-client &> /dev/null; then
    echo -e "${GREEN}✓ fail2ban installed${NC}"
else
    echo -e "${YELLOW}⚠ fail2ban not found (optional)${NC}"
fi

# ============= SCHRITT 4: SSH Port Detection =============
echo ""
echo -e "${YELLOW}[4/11] Checking SSH configuration...${NC}"

# Detect SSH port from sshd_config
SSH_CONFIG_PORT=$(grep "^Port" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
SSH_RUNNING_PORT=$(ss -tlnp 2>/dev/null | grep sshd | awk '{print $4}' | cut -d':' -f2 | head -n1)

if [ -n "$SSH_CONFIG_PORT" ]; then
    echo -e "${GREEN}✓ SSH configured on port: $SSH_CONFIG_PORT${NC}"
else
    echo -e "${YELLOW}⚠ No explicit port in sshd_config (default 22 will be used)${NC}"
    SSH_CONFIG_PORT="22"
fi

if [ -n "$SSH_RUNNING_PORT" ]; then
    echo -e "${GREEN}✓ SSH currently running on port: $SSH_RUNNING_PORT${NC}"
else
    echo -e "${YELLOW}⚠ Cannot detect running SSH port${NC}"
fi

# Verify port 4848
if [ "$SSH_CONFIG_PORT" != "4848" ] && [ "$SSH_RUNNING_PORT" != "4848" ]; then
    echo -e "${YELLOW}⚠ SSH is NOT on port 4848${NC}"
    echo -e "${YELLOW}  Config: $SSH_CONFIG_PORT, Running: $SSH_RUNNING_PORT${NC}"
    read -p "Do you want to configure SSH for port 4848? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +%Y%m%d_%H%M%S)
        sed -i 's/^#*Port .*/Port 4848/' /etc/ssh/sshd_config
        echo -e "${GREEN}✓ SSH configured for port 4848 (restart required)${NC}"
        SSH_CONFIG_PORT="4848"
    fi
fi

# ============= SCHRITT 5: Backup Current Configuration =============
echo ""
echo -e "${YELLOW}[5/11] Backing up current configuration...${NC}"

BACKUP_DIR="/root/firewall-backup-$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"

# Backup nftables if exists
if [ -f /etc/nftables.conf ]; then
    cp /etc/nftables.conf "$BACKUP_DIR/nftables.conf"
    echo -e "${GREEN}✓ Backed up nftables.conf${NC}"
fi

# Backup current iptables rules
iptables-save > "$BACKUP_DIR/iptables.rules" 2>/dev/null || true
ip6tables-save > "$BACKUP_DIR/ip6tables.rules" 2>/dev/null || true
echo -e "${GREEN}✓ Backed up current firewall rules to $BACKUP_DIR${NC}"

# ============= SCHRITT 6: Configure iptables-nft compatibility =============
echo ""
echo -e "${YELLOW}[6/11] Configuring iptables compatibility layer...${NC}"

if [ -x "/usr/sbin/iptables-nft" ]; then
    update-alternatives --set iptables /usr/sbin/iptables-nft 2>/dev/null || true
    update-alternatives --set ip6tables /usr/sbin/ip6tables-nft 2>/dev/null || true
    echo -e "${GREEN}✓ iptables-nft compatibility configured${NC}"
else
    echo -e "${YELLOW}⚠ iptables-nft not found, using standard iptables${NC}"
fi

# ============= SCHRITT 7: CRITICAL Docker Compatibility PRE-Setup =============
echo ""
echo -e "${YELLOW}[7/11] [CRITICAL] Setting up Docker compatibility layer FIRST...${NC}"

# WICHTIG: iptables Rules VOR nftables setzen für maximale Kompatibilität
echo -e "${BLUE}Adding critical iptables rules for Docker/Coolify compatibility...${NC}"

# Stelle sicher dass die DEFAULT Policy nicht auf DROP steht während wir arbeiten
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT

# CRITICAL: SSH muss IMMER funktionieren
iptables -C INPUT -p tcp --dport 4848 -j ACCEPT 2>/dev/null || \
    iptables -I INPUT 1 -p tcp --dport 4848 -j ACCEPT

# Established connections
iptables -C INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
    iptables -I INPUT 2 -m state --state ESTABLISHED,RELATED -j ACCEPT

# Loopback
iptables -C INPUT -i lo -j ACCEPT 2>/dev/null || \
    iptables -I INPUT 3 -i lo -j ACCEPT

# Web ports
iptables -C INPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null || \
    iptables -A INPUT -p tcp --dport 80 -j ACCEPT

iptables -C INPUT -p tcp --dport 443 -j ACCEPT 2>/dev/null || \
    iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# ICMP
iptables -C INPUT -p icmp -j ACCEPT 2>/dev/null || \
    iptables -A INPUT -p icmp -j ACCEPT

# Docker spezifische Rules für Coolify
if docker info &>/dev/null; then
    echo -e "${BLUE}Docker detected, ensuring Docker chains exist...${NC}"

    # Ensure Docker chains exist
    iptables -N DOCKER 2>/dev/null || true
    iptables -N DOCKER-USER 2>/dev/null || true
    iptables -N DOCKER-ISOLATION-STAGE-1 2>/dev/null || true
    iptables -N DOCKER-ISOLATION-STAGE-2 2>/dev/null || true

    # Docker forward rules
    iptables -C FORWARD -j DOCKER-USER 2>/dev/null || \
        iptables -I FORWARD -j DOCKER-USER

    iptables -C FORWARD -j DOCKER-ISOLATION-STAGE-1 2>/dev/null || \
        iptables -I FORWARD -j DOCKER-ISOLATION-STAGE-1

    iptables -C FORWARD -o docker0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
        iptables -I FORWARD -o docker0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

    iptables -C FORWARD -o docker0 -j DOCKER 2>/dev/null || \
        iptables -I FORWARD -o docker0 -j DOCKER

    iptables -C FORWARD -i docker0 ! -o docker0 -j ACCEPT 2>/dev/null || \
        iptables -I FORWARD -i docker0 ! -o docker0 -j ACCEPT

    iptables -C FORWARD -i docker0 -o docker0 -j ACCEPT 2>/dev/null || \
        iptables -I FORWARD -i docker0 -o docker0 -j ACCEPT
fi

# Save iptables rules IMMEDIATELY
if command -v netfilter-persistent &>/dev/null; then
    netfilter-persistent save &>/dev/null
    echo -e "${GREEN}✓ iptables rules saved with netfilter-persistent${NC}"
elif command -v iptables-save &>/dev/null; then
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4
    echo -e "${GREEN}✓ iptables rules saved to /etc/iptables/rules.v4${NC}"
fi

echo -e "${GREEN}✓ Docker compatibility layer established${NC}"

# ============= SCHRITT 8: Create nftables configuration =============
echo ""
echo -e "${YELLOW}[8/11] Creating nftables configuration (coexistence mode)...${NC}"

# WICHTIG: nftables mit niedrigerer Priorität als iptables
cat > /etc/nftables.conf << 'EOF'
#!/usr/sbin/nft -f

# IMPORTANT: This configuration coexists with iptables for Docker compatibility
# Priority -150 ensures nftables processes packets BEFORE iptables

flush ruleset

# Main filter table with LOWER priority to work with iptables
table inet filter {
    chain input {
        # Priority -150 = runs BEFORE iptables (priority 0)
        type filter hook input priority -150; policy accept;

        # Fast-path for established connections
        ct state established,related accept

        # Always accept loopback
        iif lo accept

        # CRITICAL: SSH must always work
        tcp dport 4848 accept comment "SSH Access"

        # Web Services
        tcp dport 80 accept comment "HTTP"
        tcp dport 443 accept comment "HTTPS"

        # ICMP
        ip protocol icmp accept
        ip6 nexthdr icmpv6 accept

        # NOTE: We do NOT drop here - let iptables handle final decision
        # This ensures Docker and other iptables users continue to work
    }

    chain forward {
        type filter hook forward priority -150; policy accept;
        # Let Docker/iptables handle forwarding decisions
    }

    chain output {
        type filter hook output priority -150; policy accept;
    }
}

# NAT table structure for coexistence (Docker will use iptables nat)
table ip nat {
    chain prerouting {
        type nat hook prerouting priority -100; policy accept;
    }

    chain postrouting {
        type nat hook postrouting priority 100; policy accept;
    }
}
EOF

echo -e "${GREEN}✓ nftables configuration created (coexistence mode)${NC}"

# ============= SCHRITT 9: Load and test configuration =============
echo ""
echo -e "${YELLOW}[9/11] Loading firewall rules...${NC}"

# Test configuration first
$NFT_CMD -c -f /etc/nftables.conf || {
    echo -e "${RED}✗ Configuration syntax error${NC}"
    exit 1
}
echo -e "${GREEN}✓ Configuration syntax OK${NC}"

# Load configuration
$NFT_CMD -f /etc/nftables.conf || {
    echo -e "${RED}✗ Failed to load configuration${NC}"
    exit 1
}
echo -e "${GREEN}✓ Firewall rules loaded${NC}"

# Enable service
systemctl enable nftables || {
    echo -e "${YELLOW}⚠ Could not enable nftables service${NC}"
}
systemctl restart nftables || {
    echo -e "${YELLOW}⚠ Could not restart nftables service${NC}"
    echo -e "${YELLOW}  Trying to load rules directly...${NC}"
    $NFT_CMD -f /etc/nftables.conf
}

# ============= SCHRITT 10: Create Boot Safety Service =============
echo ""
echo -e "${YELLOW}[10/11] Creating boot safety service...${NC}"

# Create systemd service to ensure rules survive reboot
cat > /etc/systemd/system/firewall-safety.service << 'EOF'
[Unit]
Description=Firewall Safety Service for Docker/nftables coexistence
After=network-pre.target docker.service
Before=network.target ssh.service
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/firewall-safety.sh

[Install]
WantedBy=multi-user.target
EOF

# Create the safety script
cat > /usr/local/bin/firewall-safety.sh << 'EOF'
#!/bin/bash
# Firewall Safety Script - Ensures SSH access after reboot

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# Wait a moment for network
sleep 2

# CRITICAL: Ensure SSH port 4848 is ALWAYS open
iptables -C INPUT -p tcp --dport 4848 -j ACCEPT 2>/dev/null || \
    iptables -I INPUT 1 -p tcp --dport 4848 -j ACCEPT

iptables -C INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
    iptables -I INPUT 2 -m state --state ESTABLISHED,RELATED -j ACCEPT

iptables -C INPUT -i lo -j ACCEPT 2>/dev/null || \
    iptables -I INPUT 3 -i lo -j ACCEPT

iptables -C INPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null || \
    iptables -A INPUT -p tcp --dport 80 -j ACCEPT

iptables -C INPUT -p tcp --dport 443 -j ACCEPT 2>/dev/null || \
    iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Load nftables if exists
if [ -f /etc/nftables.conf ] && command -v nft &>/dev/null; then
    nft -f /etc/nftables.conf 2>/dev/null || true
fi

# Log success
logger "Firewall safety rules applied - SSH port 4848 secured"
echo "Firewall safety rules applied" > /var/log/firewall-safety.log
date >> /var/log/firewall-safety.log
EOF

chmod +x /usr/local/bin/firewall-safety.sh

# Enable the service
systemctl daemon-reload
systemctl enable firewall-safety.service
echo -e "${GREEN}✓ Boot safety service created and enabled${NC}"

# ============= SCHRITT 11: Configure fail2ban =============
echo ""
echo -e "${YELLOW}[11/11] Configuring fail2ban...${NC}"

if [ -d "/etc/fail2ban" ]; then
    cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
# Ban IP for 10 minutes
bantime = 10m
findtime = 10m
maxretry = 5

# Use iptables for banning (better Docker compatibility)
banaction = iptables-multiport
banaction_allports = iptables-allports

[sshd]
enabled = true
port = 4848
filter = sshd
logpath = /var/log/auth.log
maxretry = 5

# Protect web services (disabled by default, enable if needed)
[nginx-http-auth]
enabled = false
filter = nginx-http-auth
port = http,https
logpath = /var/log/nginx/error.log

[nginx-limit-req]
enabled = false
filter = nginx-limit-req
port = http,https
logpath = /var/log/nginx/error.log
EOF

    systemctl restart fail2ban 2>/dev/null || {
        echo -e "${YELLOW}⚠ Could not restart fail2ban${NC}"
    }
    echo -e "${GREEN}✓ fail2ban configured with iptables backend${NC}"
else
    echo -e "${YELLOW}⚠ fail2ban directory not found${NC}"
fi

# ============= Final verification =============
echo ""
echo -e "${YELLOW}[Final] Running verification...${NC}"

# Test SSH port
echo -n "Testing SSH port 4848... "
if timeout 2 bash -c "echo >/dev/tcp/localhost/4848" 2>/dev/null; then
    echo -e "${GREEN}OPEN ✓${NC}"
else
    echo -e "${RED}BLOCKED ✗${NC}"
    echo -e "${YELLOW}Applying emergency fix...${NC}"
    iptables -I INPUT 1 -p tcp --dport 4848 -j ACCEPT
    iptables -I INPUT 2 -m state --state ESTABLISHED,RELATED -j ACCEPT
fi

# Check services
echo ""
echo -e "${BLUE}Service Status:${NC}"
for service in nftables firewall-safety fail2ban docker sshd; do
    if systemctl is-active --quiet $service 2>/dev/null; then
        echo -e "  $service: ${GREEN}active${NC}"
    else
        echo -e "  $service: ${YELLOW}inactive${NC}"
    fi
done

# Show rules
echo ""
echo -e "${BLUE}Active Rules:${NC}"
echo "  iptables SSH rules: $(iptables -L INPUT -n | grep -c 4848 || echo 0)"
echo "  nftables SSH rules: $(nft list ruleset 2>/dev/null | grep -c 4848 || echo 0)"

# ============= ABSCHLUSS =============
echo ""
echo -e "${GREEN}================================================${NC}"
echo -e "${GREEN}✓ Firewall setup completed successfully!${NC}"
echo -e "${GREEN}================================================${NC}"
echo ""
echo -e "${YELLOW}Critical Information:${NC}"
echo -e "  • SSH Port: ${YELLOW}4848${NC}"
echo -e "  • Open Ports: ${YELLOW}80, 443, 4848${NC}"
echo -e "  • Firewall Mode: ${YELLOW}iptables + nftables coexistence${NC}"
echo -e "  • Docker: ${YELLOW}Using iptables${NC}"
echo -e "  • Boot Safety: ${YELLOW}Enabled${NC}"
echo ""
echo -e "${RED}⚠ CRITICAL ACTIONS:${NC}"
echo -e "  1. ${BOLD}TEST SSH NOW:${NC} ssh -p 4848 user@this-server"
echo -e "  2. ${BOLD}Keep this session open${NC} until you confirm access"
echo -e "  3. ${BOLD}Test after reboot${NC} to ensure persistence"
echo ""
