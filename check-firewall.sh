#!/bin/bash

# ============= PATH SETUP =============
# Stelle sicher, dass alle Standard-Debian-Pfade im PATH sind
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"

# Farben für Output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ============= COMMAND DETECTION =============
# Finde Befehle auch wenn sie nicht im PATH sind
find_command() {
    local cmd=$1
    # Erst im PATH suchen
    if command -v "$cmd" &> /dev/null; then
        command -v "$cmd"
        return 0
    fi
    # Dann in Standard-Verzeichnissen suchen
    for dir in /usr/local/sbin /usr/local/bin /usr/sbin /usr/bin /sbin /bin; do
        if [ -x "$dir/$cmd" ]; then
            echo "$dir/$cmd"
            return 0
        fi
    done
    # Als letztes mit find suchen
    local found=$(find /usr /sbin /bin -name "$cmd" -type f -executable 2>/dev/null | head -1)
    if [ -n "$found" ]; then
        echo "$found"
        return 0
    fi
    return 1
}

# Befehle lokalisieren
NFT_CMD=$(find_command nft)
IPTABLES_CMD=$(find_command iptables)
IP6TABLES_CMD=$(find_command ip6tables)
SS_CMD=$(find_command ss)
NETSTAT_CMD=$(find_command netstat)
SYSTEMCTL_CMD=$(find_command systemctl)
FAIL2BAN_CMD=$(find_command fail2ban-client)
DOCKER_CMD=$(find_command docker)
JOURNALCTL_CMD=$(find_command journalctl)

# ============= HEADER =============
clear
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}                         ${BOLD}FIREWALL SECURITY CHECK${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}Host:${NC} $(hostname -f 2>/dev/null || hostname) | ${CYAN}Date:${NC} $(date '+%Y-%m-%d %H:%M:%S')"
if [ -f /etc/os-release ]; then
    echo -e "${CYAN}System:${NC} $(grep PRETTY_NAME /etc/os-release | cut -d'"' -f2)"
fi
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# ============= COMMAND AVAILABILITY CHECK =============
echo -e "${BOLD}[1/8] Command Availability Check${NC}"
echo -e "${BLUE}────────────────────────────────────────${NC}"

check_command() {
    local name=$1
    local cmd=$2
    if [ -n "$cmd" ] && [ -x "$cmd" ]; then
        echo -e "  ${GREEN}✓${NC} $name: ${CYAN}$cmd${NC}"
        return 0
    else
        echo -e "  ${RED}✗${NC} $name: ${RED}not found${NC}"
        return 1
    fi
}

check_command "nftables" "$NFT_CMD"
NFT_AVAILABLE=$?
check_command "iptables" "$IPTABLES_CMD"
check_command "fail2ban" "$FAIL2BAN_CMD"
check_command "docker" "$DOCKER_CMD"
check_command "systemctl" "$SYSTEMCTL_CMD"
echo ""

# ============= FIREWALL RULES CHECK =============
echo -e "${BOLD}[2/8] Firewall Rules Check${NC}"
echo -e "${BLUE}────────────────────────────────────────${NC}"

if [ $NFT_AVAILABLE -eq 0 ]; then
    # Check ob Port 4848 offen ist
    if $NFT_CMD list ruleset 2>/dev/null | grep -q "tcp dport 4848"; then
        echo -e "  ${GREEN}✓${NC} SSH Port 4848 is ${GREEN}OPEN${NC} in nftables"
    else
        echo -e "  ${RED}✗${NC} SSH Port 4848 is ${RED}NOT OPEN${NC} in nftables!"
    fi

    # Check ob Ports 80 und 443 offen sind
    if $NFT_CMD list ruleset 2>/dev/null | grep -q "tcp dport 80"; then
        echo -e "  ${GREEN}✓${NC} HTTP Port 80 is ${GREEN}OPEN${NC} in nftables"
    else
        echo -e "  ${YELLOW}⚠${NC} HTTP Port 80 is ${YELLOW}NOT OPEN${NC} in nftables"
    fi

    if $NFT_CMD list ruleset 2>/dev/null | grep -q "tcp dport 443"; then
        echo -e "  ${GREEN}✓${NC} HTTPS Port 443 is ${GREEN}OPEN${NC} in nftables"
    else
        echo -e "  ${YELLOW}⚠${NC} HTTPS Port 443 is ${YELLOW}NOT OPEN${NC} in nftables"
    fi

    # Zeige Anzahl der Regeln
    RULE_COUNT=$($NFT_CMD list ruleset 2>/dev/null | grep -c "tcp dport" || echo "0")
    echo -e "  ${CYAN}ℹ${NC} Total TCP port rules: ${BOLD}$RULE_COUNT${NC}"
else
    echo -e "  ${RED}✗${NC} Cannot check nftables rules (nft not available)"
fi

# Check auch iptables falls nftables nicht verfügbar
if [ $NFT_AVAILABLE -ne 0 ] && [ -n "$IPTABLES_CMD" ]; then
    echo -e "  ${YELLOW}⚠${NC} Checking iptables instead..."
    IPTABLES_RULES=$($IPTABLES_CMD -L INPUT -n 2>/dev/null | grep -E "dpt:(80|443|4848)" | wc -l)
    echo -e "  ${CYAN}ℹ${NC} iptables INPUT rules for ports 80/443/4848: ${BOLD}$IPTABLES_RULES${NC}"
fi
echo ""

# ============= NETWORK PORTS CHECK =============
echo -e "${BOLD}[3/8] Network Listening Ports${NC}"
echo -e "${BLUE}────────────────────────────────────────${NC}"

# Funktion um Ports zu checken (nutzt ss oder netstat)
check_ports() {
    local ports=""
    if [ -n "$SS_CMD" ]; then
        ports=$($SS_CMD -tlnp 2>/dev/null | grep LISTEN)
    elif [ -n "$NETSTAT_CMD" ]; then
        ports=$($NETSTAT_CMD -tlnp 2>/dev/null | grep LISTEN)
    else
        echo -e "  ${RED}✗${NC} Neither ss nor netstat available"
        return 1
    fi

    echo "$ports" | while read line; do
        if [ -z "$line" ]; then continue; fi

        PORT=$(echo $line | awk '{print $4}' | rev | cut -d':' -f1 | rev)
        PROCESS=$(echo $line | grep -oP '\(\("\K[^"]+' 2>/dev/null || echo "unknown")

        case $PORT in
            80)   echo -e "  ${GREEN}✓${NC} Port ${BOLD}80${NC}   - HTTP ${CYAN}[$PROCESS]${NC}" ;;
            443)  echo -e "  ${GREEN}✓${NC} Port ${BOLD}443${NC}  - HTTPS ${CYAN}[$PROCESS]${NC}" ;;
            4848) echo -e "  ${GREEN}✓${NC} Port ${BOLD}4848${NC} - SSH ${CYAN}[$PROCESS]${NC}" ;;
            22)   echo -e "  ${YELLOW}⚠${NC} Port ${BOLD}22${NC}   - SSH (standard) ${CYAN}[$PROCESS]${NC}" ;;
            *)
                if [[ "$line" =~ 127\.0\.0\.1 ]] || [[ "$line" =~ ::1 ]]; then
                    echo -e "  ${BLUE}○${NC} Port ${BOLD}$PORT${NC} - localhost only ${CYAN}[$PROCESS]${NC}"
                elif [[ $PORT -gt 32768 ]]; then
                    echo -e "  ${CYAN}○${NC} Port ${BOLD}$PORT${NC} - ephemeral ${CYAN}[$PROCESS]${NC}"
                elif [[ $PORT -gt 1024 ]]; then
                    echo -e "  ${YELLOW}○${NC} Port ${BOLD}$PORT${NC} - high port ${CYAN}[$PROCESS]${NC}"
                else
                    echo -e "  ${YELLOW}⚠${NC} Port ${BOLD}$PORT${NC} - system port ${CYAN}[$PROCESS]${NC}"
                fi
                ;;
        esac
    done
}

check_ports
echo ""

# ============= SERVICE STATUS CHECK =============
echo -e "${BOLD}[4/8] Service Status${NC}"
echo -e "${BLUE}────────────────────────────────────────${NC}"

check_service() {
    local service=$1
    local display_name=$2
    if [ -n "$SYSTEMCTL_CMD" ]; then
        if $SYSTEMCTL_CMD is-active --quiet $service 2>/dev/null; then
            local uptime=$($SYSTEMCTL_CMD show $service --property=ActiveEnterTimestamp --value 2>/dev/null)
            if [ -n "$uptime" ]; then
                uptime=$(date -d "$uptime" '+%Y-%m-%d %H:%M' 2>/dev/null || echo "unknown")
                echo -e "  ${GREEN}✓${NC} $display_name: ${GREEN}active${NC} (since $uptime)"
            else
                echo -e "  ${GREEN}✓${NC} $display_name: ${GREEN}active${NC}"
            fi
        elif $SYSTEMCTL_CMD list-unit-files 2>/dev/null | grep -q "^$service"; then
            echo -e "  ${RED}✗${NC} $display_name: ${RED}inactive${NC}"
        else
            echo -e "  ${YELLOW}−${NC} $display_name: ${YELLOW}not installed${NC}"
        fi
    else
        # Fallback ohne systemctl
        if pgrep -x "$service" > /dev/null 2>&1; then
            echo -e "  ${GREEN}✓${NC} $display_name: ${GREEN}running${NC}"
        else
            echo -e "  ${YELLOW}?${NC} $display_name: ${YELLOW}unknown${NC}"
        fi
    fi
}

check_service "nftables" "nftables"
check_service "fail2ban" "fail2ban"
check_service "docker" "Docker"
check_service "sshd" "SSH Server"
check_service "nginx" "Nginx"
echo ""

# ============= SSH CONFIGURATION CHECK =============
echo -e "${BOLD}[5/8] SSH Configuration${NC}"
echo -e "${BLUE}────────────────────────────────────────${NC}"

if [ -f /etc/ssh/sshd_config ]; then
    SSH_PORT=$(grep "^Port" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    if [ -n "$SSH_PORT" ]; then
        if [ "$SSH_PORT" = "4848" ]; then
            echo -e "  ${GREEN}✓${NC} SSH configured on port ${GREEN}4848${NC}"
        else
            echo -e "  ${YELLOW}⚠${NC} SSH configured on port ${YELLOW}$SSH_PORT${NC} (not 4848)"
        fi
    else
        echo -e "  ${YELLOW}⚠${NC} SSH using default port ${YELLOW}22${NC}"
    fi

    # Check weitere SSH Security Settings
    if grep -q "^PermitRootLogin no\|^PermitRootLogin prohibit-password" /etc/ssh/sshd_config 2>/dev/null; then
        echo -e "  ${GREEN}✓${NC} Root login restricted"
    else
        echo -e "  ${YELLOW}⚠${NC} Root login may be permitted"
    fi

    if grep -q "^PasswordAuthentication no" /etc/ssh/sshd_config 2>/dev/null; then
        echo -e "  ${GREEN}✓${NC} Password authentication disabled"
    else
        echo -e "  ${YELLOW}⚠${NC} Password authentication enabled"
    fi
else
    echo -e "  ${RED}✗${NC} SSH config file not found"
fi
echo ""

# ============= ACTIVE CONNECTIONS CHECK =============
echo -e "${BOLD}[6/8] Active Connections${NC}"
echo -e "${BLUE}────────────────────────────────────────${NC}"

# SSH Connections on port 4848
if [ -n "$SS_CMD" ]; then
    SSH_CONNECTIONS=$($SS_CMD -tn state established 2>/dev/null | grep -c ":4848" || echo "0")
    HTTP_CONNECTIONS=$($SS_CMD -tn state established 2>/dev/null | grep -c ":80" || echo "0")
    HTTPS_CONNECTIONS=$($SS_CMD -tn state established 2>/dev/null | grep -c ":443" || echo "0")
elif [ -n "$NETSTAT_CMD" ]; then
    SSH_CONNECTIONS=$($NETSTAT_CMD -tn 2>/dev/null | grep ESTABLISHED | grep -c ":4848" || echo "0")
    HTTP_CONNECTIONS=$($NETSTAT_CMD -tn 2>/dev/null | grep ESTABLISHED | grep -c ":80" || echo "0")
    HTTPS_CONNECTIONS=$($NETSTAT_CMD -tn 2>/dev/null | grep ESTABLISHED | grep -c ":443" || echo "0")
else
    SSH_CONNECTIONS="?"
    HTTP_CONNECTIONS="?"
    HTTPS_CONNECTIONS="?"
fi

echo -e "  SSH (4848):  ${BOLD}$SSH_CONNECTIONS${NC} connections"
echo -e "  HTTP (80):   ${BOLD}$HTTP_CONNECTIONS${NC} connections"
echo -e "  HTTPS (443): ${BOLD}$HTTPS_CONNECTIONS${NC} connections"
echo ""

# ============= FAIL2BAN STATUS =============
echo -e "${BOLD}[7/8] Fail2ban Status${NC}"
echo -e "${BLUE}────────────────────────────────────────${NC}"

if [ -n "$FAIL2BAN_CMD" ] && [ -n "$SYSTEMCTL_CMD" ] && $SYSTEMCTL_CMD is-active --quiet fail2ban 2>/dev/null; then
    # Get jail status
    JAIL_STATUS=$($FAIL2BAN_CMD status 2>/dev/null | grep "Jail list" | cut -d':' -f2 | tr -d '\t' || echo "none")
    echo -e "  Active jails: ${CYAN}$JAIL_STATUS${NC}"

    # Check SSH jail specifically
    if $FAIL2BAN_CMD status sshd &>/dev/null; then
        BANNED_IPS=$($FAIL2BAN_CMD status sshd 2>/dev/null | grep "Banned IP" | cut -d':' -f2 | tr -d '\t' || echo "")
        BAN_COUNT=$($FAIL2BAN_CMD status sshd 2>/dev/null | grep "Currently banned" | cut -d':' -f2 | tr -d '\t' || echo "0")
        TOTAL_BANNED=$($FAIL2BAN_CMD status sshd 2>/dev/null | grep "Total banned" | cut -d':' -f2 | tr -d '\t' || echo "0")

        echo -e "  SSH Jail:"
        echo -e "    Currently banned: ${BOLD}$BAN_COUNT${NC} IPs"
        echo -e "    Total banned:     ${BOLD}$TOTAL_BANNED${NC} IPs"

        if [ -n "$BANNED_IPS" ] && [ "$BANNED_IPS" != " " ]; then
            echo -e "    Banned IPs: ${RED}$BANNED_IPS${NC}"
        fi
    else
        echo -e "  ${YELLOW}⚠${NC} SSH jail not active"
    fi
else
    echo -e "  ${YELLOW}⚠${NC} Fail2ban not running or not available"
fi
echo ""

# ============= DOCKER STATUS =============
echo -e "${BOLD}[8/8] Docker Container Ports${NC}"
echo -e "${BLUE}────────────────────────────────────────${NC}"

if [ -n "$DOCKER_CMD" ] && $DOCKER_CMD info &>/dev/null; then
    CONTAINER_COUNT=$($DOCKER_CMD ps -q 2>/dev/null | wc -l)
    echo -e "  Running containers: ${BOLD}$CONTAINER_COUNT${NC}"

    if [ $CONTAINER_COUNT -gt 0 ]; then
        echo -e "  ${CYAN}Exposed ports:${NC}"
        $DOCKER_CMD ps --format "table {{.Names}}\t{{.Ports}}" 2>/dev/null | tail -n +2 | while IFS=$'\t' read -r name ports; do
            if [ -n "$ports" ] && [ "$ports" != "" ]; then
                # Parse ports besser
                ports=$(echo $ports | sed 's/0.0.0.0://g' | sed 's/->/ → /g')
                echo -e "    ${CYAN}$name${NC}: $ports"
            else
                echo -e "    ${CYAN}$name${NC}: no exposed ports"
            fi
        done
    fi
else
    echo -e "  ${YELLOW}⚠${NC} Docker not running or not available"
fi
echo ""

# ============= SUMMARY =============
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}Summary & Recommendations${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

ISSUES=0

# Check critical ports
if [ $NFT_AVAILABLE -eq 0 ]; then
    if ! $NFT_CMD list ruleset 2>/dev/null | grep -q "tcp dport 4848"; then
        echo -e "${RED}⚠ CRITICAL:${NC} SSH port 4848 is not open in firewall!"
        ISSUES=$((ISSUES + 1))
    fi
fi

# Check if services are running
if [ -n "$SYSTEMCTL_CMD" ]; then
    if ! $SYSTEMCTL_CMD is-active --quiet nftables 2>/dev/null; then
        echo -e "${RED}⚠ WARNING:${NC} nftables service is not running"
        ISSUES=$((ISSUES + 1))
    fi

    if ! $SYSTEMCTL_CMD is-active --quiet sshd 2>/dev/null; then
        echo -e "${RED}⚠ CRITICAL:${NC} SSH service is not running"
        ISSUES=$((ISSUES + 1))
    fi
fi

if [ $ISSUES -eq 0 ]; then
    echo -e "${GREEN}✓ All checks passed!${NC} Firewall configuration appears to be correct."
else
    echo -e "${YELLOW}Found $ISSUES issue(s) that need attention.${NC}"
fi

echo ""
echo -e "${CYAN}Quick Actions:${NC}"
echo -e "  • Test SSH:  ${BOLD}ssh -p 4848 user@$(hostname -I 2>/dev/null | awk '{print $1}')${NC}"
echo -e "  • Show logs: ${BOLD}journalctl -xe | grep -E 'nftables|fail2ban' | tail -20${NC}"
echo -e "  • Reload FW: ${BOLD}nft -f /etc/nftables.conf${NC}"
echo ""

# ============= EXPORT REPORT =============
# Optional: Save report to file
if [ "$1" = "--save" ]; then
    REPORT_FILE="/root/firewall-check-$(date +%Y%m%d-%H%M%S).log"
    {
        echo "Firewall Security Check Report"
        echo "Generated: $(date)"
        echo "================================"
        "$0" | sed 's/\x1b\[[0-9;]*m//g'  # Remove color codes
    } > "$REPORT_FILE"
    echo -e "${GREEN}Report saved to: $REPORT_FILE${NC}"
fi

# Ende des Scripts
exit 0
