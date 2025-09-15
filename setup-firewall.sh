#!/bin/bash

# ============================================================================
#                        FIREWALL SETUP SCRIPT V2
#                     With Common Library Integration
# ============================================================================

# Source common library
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/lib/common.sh" ]; then
    source "$SCRIPT_DIR/lib/common.sh"
elif [ -f "/opt/vps-config/lib/common.sh" ]; then
    source "/opt/vps-config/lib/common.sh"
else
    echo "Error: common.sh not found"
    exit 1
fi

# Initialize
init_common

echo -e "${BLUE}================================================${NC}"
echo -e "${BLUE}   Unified Firewall Setup for Debian 12/13 V2 ${NC}"
echo -e "${BLUE}================================================${NC}"
echo ""

# ============= STEP 1: System Checks =============
echo -e "${YELLOW}[1/11] Running system compatibility checks...${NC}"

check_debian || log_warning "Non-Debian system detected"
log_success "System check completed"

# ============= STEP 2: Package Installation =============
echo ""
echo -e "${YELLOW}[2/11] Installing required packages...${NC}"

# Define required packages
FIREWALL_PACKAGES=(
    "nftables"
    "iptables"
    "netfilter-persistent"
    "iptables-persistent"
    "net-tools"
    "fail2ban"
)

# Install using common library function
install_packages FIREWALL_PACKAGES true

# ============= STEP 3: Verify Installation =============
echo ""
echo -e "${YELLOW}[3/11] Verifying installations...${NC}"

# Find nft command
NFT_CMD=$(find_command nft)
if [ -z "$NFT_CMD" ]; then
    log_error "nft command not found"
    exit 1
fi
log_success "nft found at: $NFT_CMD"

# Check version
NFT_VERSION=$($NFT_CMD --version 2>/dev/null | head -n1) || NFT_VERSION="unknown"
log_success "nftables version: $NFT_VERSION"

# Check iptables
IPTABLES_CMD=$(find_command iptables)
if [ -z "$IPTABLES_CMD" ]; then
    log_error "iptables not found"
    exit 1
fi
log_success "iptables found at: $IPTABLES_CMD"

# ============= STEP 4: SSH Port Detection =============
echo ""
echo -e "${YELLOW}[4/11] Checking SSH configuration...${NC}"

# Use common library function
detect_ssh_port
ensure_ssh_port_4848

# ============= STEP 5: Backup Configuration =============
echo ""
echo -e "${YELLOW}[5/11] Backing up current configuration...${NC}"

# Use common library backup function
create_backup "/etc/nftables.conf" "firewall"
iptables-save > "$BACKUP_BASE_DIR/firewall/iptables.rules.$(date +%Y%m%d_%H%M%S)" 2>/dev/null || true
log_success "Firewall configuration backed up"

# ============= STEP 6: Configure iptables-nft compatibility =============
echo ""
echo -e "${YELLOW}[6/11] Configuring iptables compatibility layer...${NC}"

if [ -x "/usr/sbin/iptables-nft" ]; then
    update-alternatives --set iptables /usr/sbin/iptables-nft 2>/dev/null || true
    update-alternatives --set ip6tables /usr/sbin/ip6tables-nft 2>/dev/null || true
    log_success "iptables-nft compatibility configured"
else
    log_warning "iptables-nft not found, using standard iptables"
fi

# ============= STEP 7: Docker Compatibility Setup =============
echo ""
echo -e "${YELLOW}[7/11] Setting up Docker compatibility layer...${NC}"

# Set up iptables rules for Docker
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT

# Critical SSH rule
iptables -C INPUT -p tcp --dport $SSH_PORT -j ACCEPT 2>/dev/null || \
    iptables -I INPUT 1 -p tcp --dport $SSH_PORT -j ACCEPT

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

# Docker specific rules if Docker is installed
if command -v docker &>/dev/null; then
    log_info "Docker detected, ensuring Docker chains exist..."

    # Create filter table chains
    iptables -N DOCKER 2>/dev/null || true
    iptables -N DOCKER-USER 2>/dev/null || true
    iptables -N DOCKER-ISOLATION-STAGE-1 2>/dev/null || true
    iptables -N DOCKER-ISOLATION-STAGE-2 2>/dev/null || true

    # Create NAT table chains (required for port forwarding)
    iptables -t nat -N DOCKER 2>/dev/null || true

    # Add DOCKER chain to PREROUTING and OUTPUT in NAT table
    iptables -t nat -C PREROUTING -m addrtype --dst-type LOCAL -j DOCKER 2>/dev/null || \
        iptables -t nat -A PREROUTING -m addrtype --dst-type LOCAL -j DOCKER

    iptables -t nat -C OUTPUT ! -d 127.0.0.0/8 -m addrtype --dst-type LOCAL -j DOCKER 2>/dev/null || \
        iptables -t nat -A OUTPUT ! -d 127.0.0.0/8 -m addrtype --dst-type LOCAL -j DOCKER

    # Add DOCKER-USER to FORWARD chain
    iptables -C FORWARD -j DOCKER-USER 2>/dev/null || \
        iptables -I FORWARD -j DOCKER-USER

    log_success "Docker compatibility configured (filter and NAT tables)"
fi

# Save iptables rules
if command -v netfilter-persistent &>/dev/null; then
    netfilter-persistent save &>/dev/null
    log_success "iptables rules saved"
fi

# ============= STEP 8: Create nftables configuration =============
echo ""
echo -e "${YELLOW}[8/11] Creating nftables configuration...${NC}"

cat > /etc/nftables.conf << EOF
#!/usr/sbin/nft -f

# VPS Firewall Configuration V2
# Coexists with iptables for Docker compatibility

flush ruleset

table inet filter {
    chain input {
        type filter hook input priority -150; policy accept;

        ct state established,related accept
        iif lo accept

        # SSH on port $SSH_PORT
        tcp dport $SSH_PORT accept comment "SSH Access"

        # Web Services
        tcp dport 80 accept comment "HTTP"
        tcp dport 443 accept comment "HTTPS"

        # ICMP
        ip protocol icmp accept
        ip6 nexthdr icmpv6 accept
    }

    chain forward {
        type filter hook forward priority -150; policy accept;
    }

    chain output {
        type filter hook output priority -150; policy accept;
    }
}

table ip nat {
    chain prerouting {
        type nat hook prerouting priority -100; policy accept;
    }

    chain postrouting {
        type nat hook postrouting priority 100; policy accept;
    }
}
EOF

log_success "nftables configuration created"

# ============= STEP 9: Load configuration =============
echo ""
echo -e "${YELLOW}[9/11] Loading firewall rules...${NC}"

$NFT_CMD -c -f /etc/nftables.conf || {
    log_error "Configuration syntax error"
    exit 1
}
log_success "Configuration syntax OK"

$NFT_CMD -f /etc/nftables.conf || {
    log_error "Failed to load configuration"
    exit 1
}
log_success "Firewall rules loaded"

# Enable service using common library
manage_service "nftables" "enable"
manage_service "nftables" "restart"

# ============= STEP 10: Create Boot Safety Service =============
echo ""
echo -e "${YELLOW}[10/11] Creating boot safety service...${NC}"

cat > /etc/systemd/system/firewall-safety.service << 'EOF'
[Unit]
Description=Firewall Safety Service
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

cat > /usr/local/bin/firewall-safety.sh << EOF
#!/bin/bash
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

sleep 2

# Ensure SSH port is always open
iptables -C INPUT -p tcp --dport $SSH_PORT -j ACCEPT 2>/dev/null || \
    iptables -I INPUT 1 -p tcp --dport $SSH_PORT -j ACCEPT

iptables -C INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
    iptables -I INPUT 2 -m state --state ESTABLISHED,RELATED -j ACCEPT

# Load nftables
[ -f /etc/nftables.conf ] && nft -f /etc/nftables.conf 2>/dev/null || true

logger "Firewall safety rules applied - SSH port $SSH_PORT secured"
EOF

chmod +x /usr/local/bin/firewall-safety.sh

systemctl daemon-reload
manage_service "firewall-safety" "enable"
log_success "Boot safety service created"

# ============= STEP 11: Configure fail2ban =============
echo ""
echo -e "${YELLOW}[11/11] Configuring fail2ban...${NC}"

if [ -d "/etc/fail2ban" ]; then
    FIREWALL_BACKEND=$(detect_firewall_backend)

    cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 10m
findtime = 10m
maxretry = 5

$(if [ "$FIREWALL_BACKEND" = "nftables" ]; then
    echo "banaction = nftables-multiport"
else
    echo "banaction = iptables-multiport"
fi)

[sshd]
enabled = true
port = $SSH_PORT
filter = sshd
logpath = /var/log/auth.log
maxretry = 5
EOF

    manage_service "fail2ban" "restart"
    log_success "fail2ban configured with $FIREWALL_BACKEND backend"
else
    log_warning "fail2ban directory not found"
fi

# ============= Final Verification =============
echo ""
echo -e "${YELLOW}[Final] Running verification...${NC}"

# Test SSH port using common library
if test_port "$SSH_PORT"; then
    log_success "SSH port $SSH_PORT is OPEN"
else
    log_error "SSH port $SSH_PORT is BLOCKED"
    iptables -I INPUT 1 -p tcp --dport $SSH_PORT -j ACCEPT
    log_warning "Emergency rule added"
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

# ============= SUMMARY =============
echo ""
echo -e "${GREEN}================================================${NC}"
echo -e "${GREEN}✓ Firewall setup completed successfully!${NC}"
echo -e "${GREEN}================================================${NC}"
echo ""
echo -e "${YELLOW}Configuration:${NC}"
echo -e "  • SSH Port: ${YELLOW}$SSH_PORT${NC}"
echo -e "  • Open Ports: ${YELLOW}80, 443, $SSH_PORT${NC}"
echo -e "  • Firewall Mode: ${YELLOW}iptables + nftables coexistence${NC}"
echo -e "  • Backend: ${YELLOW}$(detect_firewall_backend)${NC}"
echo ""
echo -e "${RED}⚠ TEST SSH NOW:${NC} ssh -p $SSH_PORT user@$(get_public_ip)"
echo ""

exit 0
