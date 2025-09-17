#!/bin/bash

# ============================================================================
#                     FIX COOLIFY/DOCKER NAT ISSUES
#           Behebt DNAT/Port-Forwarding Probleme nach Firewall-Setup
# ============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}================================================${NC}"
echo -e "${BLUE}     Coolify/Docker NAT Fix für VPS            ${NC}"
echo -e "${BLUE}================================================${NC}"
echo ""

# Detect main network interface
MAIN_IFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
if [ -z "$MAIN_IFACE" ]; then
    MAIN_IFACE="ens3"  # Fallback
fi
echo -e "${GREEN}✓${NC} Detected network interface: ${MAIN_IFACE}"

echo -e "\n${YELLOW}[1/5] Resetting iptables NAT table...${NC}"
# Flush NAT table (careful!)
iptables -t nat -F DOCKER 2>/dev/null || true
iptables -t nat -F 2>/dev/null || true

echo -e "${YELLOW}[2/5] Creating Docker NAT chains...${NC}"
# Create all required Docker chains in NAT table
iptables -t nat -N DOCKER 2>/dev/null || true

# Add Docker to PREROUTING and OUTPUT
iptables -t nat -C PREROUTING -m addrtype --dst-type LOCAL -j DOCKER 2>/dev/null || \
    iptables -t nat -I PREROUTING -m addrtype --dst-type LOCAL -j DOCKER

iptables -t nat -C OUTPUT ! -d 127.0.0.0/8 -m addrtype --dst-type LOCAL -j DOCKER 2>/dev/null || \
    iptables -t nat -I OUTPUT ! -d 127.0.0.0/8 -m addrtype --dst-type LOCAL -j DOCKER

echo -e "${YELLOW}[3/5] Setting up MASQUERADE for container networks...${NC}"

# CRITICAL: Use correct output interface!
# Standard Docker networks
iptables -t nat -C POSTROUTING -s 172.16.0.0/12 -o ${MAIN_IFACE} -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -s 172.16.0.0/12 -o ${MAIN_IFACE} -j MASQUERADE

# Default Docker bridge
iptables -t nat -C POSTROUTING -s 172.17.0.0/16 -o ${MAIN_IFACE} -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -s 172.17.0.0/16 -o ${MAIN_IFACE} -j MASQUERADE

# Coolify custom networks (10.x.x.x range)
iptables -t nat -C POSTROUTING -s 10.0.0.0/8 -o ${MAIN_IFACE} -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -s 10.0.0.0/8 -o ${MAIN_IFACE} -j MASQUERADE

# Generic rule for any bridge networks (covers all cases)
iptables -t nat -C POSTROUTING -m addrtype --src-type LOCAL -o ${MAIN_IFACE} -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -m addrtype --src-type LOCAL -o ${MAIN_IFACE} -j MASQUERADE

echo -e "${GREEN}✓${NC} MASQUERADE rules configured for interface ${MAIN_IFACE}"

echo -e "\n${YELLOW}[4/5] Ensuring FORWARD chain allows Docker traffic...${NC}"
# Ensure FORWARD policy allows Docker
iptables -P FORWARD ACCEPT

# Docker-specific FORWARD rules
iptables -C FORWARD -j DOCKER-USER 2>/dev/null || iptables -I FORWARD -j DOCKER-USER
iptables -C FORWARD -j DOCKER-ISOLATION-STAGE-1 2>/dev/null || iptables -A FORWARD -j DOCKER-ISOLATION-STAGE-1
iptables -C FORWARD -o docker0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
    iptables -A FORWARD -o docker0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -C FORWARD -o docker0 -j DOCKER 2>/dev/null || iptables -A FORWARD -o docker0 -j DOCKER
iptables -C FORWARD -i docker0 ! -o docker0 -j ACCEPT 2>/dev/null || \
    iptables -A FORWARD -i docker0 ! -o docker0 -j ACCEPT
iptables -C FORWARD -i docker0 -o docker0 -j ACCEPT 2>/dev/null || \
    iptables -A FORWARD -i docker0 -o docker0 -j ACCEPT

echo -e "${GREEN}✓${NC} FORWARD chain configured for Docker"

echo -e "\n${YELLOW}[5/5] Restarting Docker to apply changes...${NC}"
systemctl restart docker || {
    echo -e "${RED}✗${NC} Failed to restart Docker"
    echo "Try manually: systemctl restart docker"
}

# Save rules
if command -v netfilter-persistent &>/dev/null; then
    netfilter-persistent save &>/dev/null
    echo -e "${GREEN}✓${NC} Rules saved persistently"
fi

echo -e "\n${BLUE}================================================${NC}"
echo -e "${GREEN}NAT fix completed!${NC}"
echo -e "\nVerify with:"
echo -e "  ${BLUE}iptables -t nat -L -n -v${NC}  # Check NAT rules"
echo -e "  ${BLUE}docker ps${NC}                  # Check containers"
echo -e "  ${BLUE}docker network ls${NC}          # Check networks"
echo -e "\nIf Coolify is still having issues, restart it:"
echo -e "  ${BLUE}cd /data/coolify && docker compose restart${NC}"
