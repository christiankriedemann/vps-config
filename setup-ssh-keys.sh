#!/bin/bash

# ============================================================================
#                        SSH KEY SETUP HELPER SCRIPT
#                     Sichere SSH-Key Konfiguration für VPS
# ============================================================================

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Configuration
SSH_PORT="${SSH_PORT:-4848}"
SSH_DIR="$HOME/.ssh"
AUTHORIZED_KEYS="$SSH_DIR/authorized_keys"

# Get public IP
PUBLIC_IP=$(curl -s -4 ifconfig.me 2>/dev/null || curl -s -4 icanhazip.com 2>/dev/null || echo "SERVER-IP")

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}                         SSH KEY SETUP HELPER${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${YELLOW}⚠ Running as user: $USER${NC}"
else
    echo -e "${GREEN}✓ Running as root${NC}"
fi

# Check current SSH keys
echo ""
echo -e "${CYAN}Current SSH Key Status:${NC}"
if [ -f "$AUTHORIZED_KEYS" ] && [ -s "$AUTHORIZED_KEYS" ]; then
    KEY_COUNT=$(grep -c "^ssh-" "$AUTHORIZED_KEYS" 2>/dev/null || echo "0")
    echo -e "${GREEN}✓ $KEY_COUNT SSH key(s) already configured${NC}"
    echo ""
    echo -e "${CYAN}Configured keys:${NC}"
    grep "^ssh-" "$AUTHORIZED_KEYS" | cut -d' ' -f3 | while read comment; do
        echo -e "  • $comment"
    done
else
    echo -e "${RED}✗ No SSH keys configured yet${NC}"
    mkdir -p "$SSH_DIR"
    chmod 700 "$SSH_DIR"
    touch "$AUTHORIZED_KEYS"
    chmod 600 "$AUTHORIZED_KEYS"
    echo -e "${GREEN}✓ Created SSH directory and authorized_keys file${NC}"
fi

echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}                 ANLEITUNG: SSH-KEY EINRICHTEN${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

echo -e "${BOLD}══════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}SCHRITT 1: AUF DEINEM LOKALEN COMPUTER${NC}"
echo -e "${BOLD}══════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${YELLOW}Option A: Windows (PowerShell)${NC}"
echo -e "────────────────────────────────"
echo -e "${GREEN}# Key erstellen:${NC}"
echo -e "ssh-keygen -t ed25519 -C \"dein-name@example.com\""
echo ""
echo -e "${GREEN}# Public Key anzeigen:${NC}"
echo -e "type \$env:USERPROFILE\\.ssh\\id_ed25519.pub"
echo ""
echo -e "${GREEN}# Key zum Server kopieren:${NC}"
echo -e "type \$env:USERPROFILE\\.ssh\\id_ed25519.pub | ssh -p $SSH_PORT root@$PUBLIC_IP \"cat >> ~/.ssh/authorized_keys\""
echo ""

echo -e "${YELLOW}Option B: Linux/Mac${NC}"
echo -e "────────────────────────────────"
echo -e "${GREEN}# Key erstellen:${NC}"
echo -e "ssh-keygen -t ed25519 -C \"dein-name@example.com\""
echo ""
echo -e "${GREEN}# Public Key anzeigen:${NC}"
echo -e "cat ~/.ssh/id_ed25519.pub"
echo ""
echo -e "${GREEN}# Key zum Server kopieren (einfachste Methode):${NC}"
echo -e "ssh-copy-id -p $SSH_PORT root@$PUBLIC_IP"
echo ""

echo -e "${BOLD}══════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}SCHRITT 2: PUBLIC KEY MANUELL HINZUFÜGEN${NC}"
echo -e "${BOLD}══════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${YELLOW}Falls ssh-copy-id nicht funktioniert:${NC}"
echo ""
echo -e "1. ${GREEN}Kopiere deinen Public Key${NC} (der mit 'ssh-ed25519' beginnt)"
echo ""
echo -e "2. ${GREEN}Füge ihn auf diesem Server ein:${NC}"
echo -e "   echo \"DEIN-PUBLIC-KEY-HIER\" >> $AUTHORIZED_KEYS"
echo ""
echo -e "   ${YELLOW}Beispiel:${NC}"
echo -e "   echo \"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... user@computer\" >> $AUTHORIZED_KEYS"
echo ""

echo -e "${BOLD}══════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}SCHRITT 3: SSH-CONFIG EINRICHTEN (Optional)${NC}"
echo -e "${BOLD}══════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${YELLOW}Auf deinem lokalen Computer (~/.ssh/config):${NC}"
echo ""
echo -e "${GREEN}Host vps"
echo -e "    HostName $PUBLIC_IP"
echo -e "    Port $SSH_PORT"
echo -e "    User root"
echo -e "    IdentityFile ~/.ssh/id_ed25519"
echo -e "    ServerAliveInterval 60"
echo -e "    ServerAliveCountMax 3${NC}"
echo ""
echo -e "${YELLOW}Dann verbindest du einfach mit:${NC} ${GREEN}ssh vps${NC}"
echo ""

echo -e "${BOLD}══════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}SCHRITT 4: VERBINDUNG TESTEN${NC}"
echo -e "${BOLD}══════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${GREEN}# Mit Key-File:${NC}"
echo -e "ssh -p $SSH_PORT -i ~/.ssh/id_ed25519 root@$PUBLIC_IP"
echo ""
echo -e "${GREEN}# Mit SSH-Config:${NC}"
echo -e "ssh vps"
echo ""

# Interactive key addition
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}                    INTERAKTIVE KEY-EINGABE${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${CYAN}Möchtest du jetzt einen SSH-Key hinzufügen? (y/n)${NC}"
read -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo ""
    echo -e "${YELLOW}Füge deinen Public Key ein (eine Zeile, Enter zum Bestätigen):${NC}"
    echo -e "${CYAN}Format: ssh-ed25519 AAAAC3NzaC1... comment${NC}"
    echo ""
    read -r PUBLIC_KEY

    if [[ "$PUBLIC_KEY" =~ ^ssh-(rsa|ed25519|ecdsa) ]]; then
        echo "$PUBLIC_KEY" >> "$AUTHORIZED_KEYS"
        echo -e "${GREEN}✓ Key wurde hinzugefügt!${NC}"

        # Set correct permissions
        chmod 600 "$AUTHORIZED_KEYS"
        chmod 700 "$SSH_DIR"

        # Count keys again
        KEY_COUNT=$(grep -c "^ssh-" "$AUTHORIZED_KEYS")
        echo -e "${GREEN}✓ Du hast jetzt $KEY_COUNT SSH-Key(s) konfiguriert${NC}"

        echo ""
        echo -e "${YELLOW}WICHTIG: Teste JETZT die Verbindung in einem NEUEN Terminal:${NC}"
        echo -e "${GREEN}ssh -p $SSH_PORT root@$PUBLIC_IP${NC}"
    else
        echo -e "${RED}✗ Ungültiges Key-Format. Der Key muss mit 'ssh-rsa', 'ssh-ed25519' oder 'ssh-ecdsa' beginnen${NC}"
    fi
fi

# Security recommendations
echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}                    SICHERHEITS-EMPFEHLUNGEN${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Check if password auth is still enabled
if grep -q "^PasswordAuthentication yes" /etc/ssh/sshd_config 2>/dev/null; then
    echo -e "${YELLOW}⚠ Password-Authentication ist noch aktiviert${NC}"
    echo ""
    echo -e "${CYAN}Nach erfolgreichem Key-Test solltest du Password-Auth deaktivieren:${NC}"
    echo -e "${GREEN}sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config${NC}"
    echo -e "${GREEN}systemctl restart sshd${NC}"
else
    echo -e "${GREEN}✓ Password-Authentication ist bereits deaktiviert${NC}"
fi

echo ""
echo -e "${RED}⚠ WARNUNG VOR REBOOT:${NC}"
echo -e "  1. ${YELLOW}Teste SSH-Verbindung mit Key in NEUEM Terminal${NC}"
echo -e "  2. ${YELLOW}Halte aktuelle Session offen bis Key funktioniert${NC}"
echo -e "  3. ${YELLOW}Erst dann reboot durchführen${NC}"
echo ""

# Final status
if [ -f "$AUTHORIZED_KEYS" ] && [ -s "$AUTHORIZED_KEYS" ]; then
    KEY_COUNT=$(grep -c "^ssh-" "$AUTHORIZED_KEYS" 2>/dev/null || echo "0")
    if [ "$KEY_COUNT" -gt 0 ]; then
        echo -e "${GREEN}✓ BEREIT: Du hast $KEY_COUNT SSH-Key(s) konfiguriert${NC}"
        echo -e "${GREEN}  Du kannst sicher rebooten nachdem du die Verbindung getestet hast${NC}"
    else
        echo -e "${RED}✗ NICHT BEREIT: Keine gültigen SSH-Keys gefunden${NC}"
        echo -e "${RED}  Richte ERST einen SSH-Key ein bevor du rebootest!${NC}"
    fi
else
    echo -e "${RED}✗ NICHT BEREIT: Keine SSH-Keys konfiguriert${NC}"
    echo -e "${RED}  Richte ERST einen SSH-Key ein bevor du rebootest!${NC}"
fi

echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

exit 0
