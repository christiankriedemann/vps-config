#!/bin/bash
# Fix missing Docker NAT chains for existing installations
# This script repairs Docker networking after firewall hardening

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color
BOLD='\033[1m'

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}Docker Firewall Chain Repair Script${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: This script must be run as root${NC}"
    exit 1
fi

# Check if Docker is installed
if ! command -v docker &>/dev/null; then
    echo -e "${YELLOW}Warning: Docker is not installed${NC}"
    echo "This script is only needed for systems running Docker."
    exit 0
fi

# Check if iptables is available
if ! command -v iptables &>/dev/null; then
    echo -e "${RED}Error: iptables is not available${NC}"
    echo "Please install iptables-nft package first:"
    echo "  apt-get update && apt-get install -y iptables"
    exit 1
fi

echo -e "${YELLOW}Checking current Docker chain status...${NC}"
echo ""

# Function to check if a chain exists
check_chain() {
    local table=$1
    local chain=$2

    if [ "$table" = "filter" ]; then
        iptables -L "$chain" -n &>/dev/null 2>&1
    else
        iptables -t "$table" -L "$chain" -n &>/dev/null 2>&1
    fi
}

# Check and create filter table chains
echo -e "${BLUE}[1/3] Checking filter table chains...${NC}"
FILTER_CHAINS=("DOCKER" "DOCKER-USER" "DOCKER-ISOLATION-STAGE-1" "DOCKER-ISOLATION-STAGE-2")
FILTER_FIXED=0

for chain in "${FILTER_CHAINS[@]}"; do
    if check_chain filter "$chain"; then
        echo -e "  ${GREEN}✔${NC} $chain already exists"
    else
        echo -e "  ${YELLOW}⚠${NC} Creating $chain..."
        iptables -N "$chain" 2>/dev/null || true
        FILTER_FIXED=$((FILTER_FIXED + 1))
        echo -e "  ${GREEN}✔${NC} $chain created"
    fi
done

# Add DOCKER-USER to FORWARD if missing
if ! iptables -C FORWARD -j DOCKER-USER 2>/dev/null; then
    echo -e "  ${YELLOW}⚠${NC} Adding DOCKER-USER to FORWARD chain..."
    iptables -I FORWARD -j DOCKER-USER
    echo -e "  ${GREEN}✔${NC} DOCKER-USER added to FORWARD"
    FILTER_FIXED=$((FILTER_FIXED + 1))
fi

echo ""

# Check and create NAT table chains
echo -e "${BLUE}[2/3] Checking NAT table chains...${NC}"
NAT_FIXED=0

if check_chain nat "DOCKER"; then
    echo -e "  ${GREEN}✔${NC} DOCKER chain in NAT table already exists"
else
    echo -e "  ${YELLOW}⚠${NC} Creating DOCKER chain in NAT table..."
    iptables -t nat -N DOCKER 2>/dev/null || true
    NAT_FIXED=$((NAT_FIXED + 1))
    echo -e "  ${GREEN}✔${NC} DOCKER chain created in NAT table"
fi

# Check and add DOCKER to PREROUTING
if ! iptables -t nat -L PREROUTING -n 2>/dev/null | grep -q "DOCKER"; then
    echo -e "  ${YELLOW}⚠${NC} Adding DOCKER to PREROUTING chain..."
    iptables -t nat -A PREROUTING -m addrtype --dst-type LOCAL -j DOCKER
    echo -e "  ${GREEN}✔${NC} DOCKER added to PREROUTING"
    NAT_FIXED=$((NAT_FIXED + 1))
else
    echo -e "  ${GREEN}✔${NC} DOCKER already in PREROUTING chain"
fi

# Check and add DOCKER to OUTPUT
if ! iptables -t nat -L OUTPUT -n 2>/dev/null | grep -q "DOCKER"; then
    echo -e "  ${YELLOW}⚠${NC} Adding DOCKER to OUTPUT chain..."
    iptables -t nat -A OUTPUT ! -d 127.0.0.0/8 -m addrtype --dst-type LOCAL -j DOCKER
    echo -e "  ${GREEN}✔${NC} DOCKER added to OUTPUT"
    NAT_FIXED=$((NAT_FIXED + 1))
else
    echo -e "  ${GREEN}✔${NC} DOCKER already in OUTPUT chain"
fi

echo ""

# Restart Docker to repopulate chains
echo -e "${BLUE}[3/3] Restarting Docker to populate chains...${NC}"

if [ $FILTER_FIXED -gt 0 ] || [ $NAT_FIXED -gt 0 ]; then
    echo -e "${YELLOW}Changes were made. Restarting Docker...${NC}"
    systemctl restart docker

    # Wait for Docker to be ready
    sleep 3

    if docker info &>/dev/null; then
        echo -e "${GREEN}✔${NC} Docker restarted successfully"
    else
        echo -e "${RED}✗${NC} Docker failed to restart. Check logs with: journalctl -xeu docker"
        exit 1
    fi
else
    echo -e "${GREEN}✔${NC} No changes needed, Docker chains were already properly configured"
fi

echo ""

# Save iptables rules
if command -v netfilter-persistent &>/dev/null; then
    echo -e "${YELLOW}Saving iptables rules...${NC}"
    netfilter-persistent save
    echo -e "${GREEN}✔${NC} Rules saved persistently"
elif command -v iptables-save &>/dev/null; then
    echo -e "${YELLOW}Saving iptables rules...${NC}"
    iptables-save > /etc/iptables/rules.v4 2>/dev/null || \
    iptables-save > /etc/iptables.rules 2>/dev/null || \
    echo -e "${YELLOW}⚠${NC} Could not save rules automatically"
fi

echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}${BOLD}Docker firewall chains repair completed!${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Show current status
echo -e "${CYAN}Current Docker status:${NC}"
docker ps --format "table {{.Names}}\t{{.Status}}" 2>/dev/null | head -5

echo ""
echo -e "${CYAN}To verify the fix, try:${NC}"
echo "  docker compose up -d     # In your project directory"
echo "  ./check-firewall.sh      # To see full firewall status"
echo ""
