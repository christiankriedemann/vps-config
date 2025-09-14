# VPS Server Setup - Debian

Automatisierte Sicherheitskonfiguration für Debian VPS Server mit Firewall, Fail2ban und SSH-Härtung.

## 🚀 Schnellstart (One-Liner Installation)

Komplette automatische Installation mit einem Befehl:

```bash
curl -sSL https://raw.githubusercontent.com/christiankriedemann/vps-config/main/setup.sh | sudo bash
```

Alternative mit wget:

```bash
wget -qO- https://raw.githubusercontent.com/christiankriedemann/vps-config/main/setup.sh | sudo bash
```

Dieser Befehl führt automatisch aus:

- ✅ Vollständiges System-Update
- ✅ Installation aller benötigten Pakete
- ✅ Firewall-Konfiguration (nftables + iptables)
- ✅ Fail2ban Setup mit Brute-Force-Schutz
- ✅ SSH-Härtung auf Port 4848
- ✅ Monitoring-Tools Installation
- ✅ Automatische Verifizierung

## 📋 Voraussetzungen

- Frischer Debian Server (11/12/13) oder Ubuntu (20.04/22.04)
- Root oder sudo Zugang
- Mindestens 512MB RAM
- Aktive Internetverbindung

## 🛠️ Was wird installiert?

### Sicherheits-Komponenten

- **Firewall**: nftables + iptables (Dual-Stack für Docker-Kompatibilität)
- **Intrusion Prevention**: fail2ban mit angepassten Jails
- **SSH**: Gehärtet auf Port 4848
- **Monitoring**: htop, iftop, vnstat, nethogs
- **Audit**: auditd, aide, rkhunter
- **Antivirus**: clamav (optional)

### Konfigurierte Ports

- **4848**: SSH (gehärtet)
- **80**: HTTP
- **443**: HTTPS
- **Alle anderen**: Blockiert

## 📦 Manuelle Installation (Alternative)

Falls Sie die Scripts einzeln ausführen möchten:

### Schritt 1: Repository klonen

```bash
git clone https://github.com/christiankriedemann/vps-config.git
cd vps-config
chmod +x *.sh
```

### Schritt 2: Scripts in korrekter Reihenfolge ausführen

**⚠️ WICHTIG: Reihenfolge MUSS eingehalten werden!**

```bash
# 1. ZUERST Firewall Setup
sudo ./setup-firewall.sh

# 2. SSH SOFORT testen (neue Session!)
ssh -p 4848 user@your-server

# 3. DANN Fail2ban Setup
sudo ./setup-fail2ban.sh

# 4. Verifizierung
sudo ./check-firewall.sh
```

## 🔧 Management-Befehle

Nach der Installation stehen folgende Befehle zur Verfügung:

### VPS Management Tool

```bash
vps-manage check        # Kompletter Security-Check
vps-manage firewall     # Firewall-Regeln anzeigen
vps-manage fail2ban     # Fail2ban Status
vps-manage ssh-test     # SSH Port 4848 testen
```

### Fail2ban Management

```bash
f2b-manage status       # Alle Jails anzeigen
f2b-manage stats        # Statistiken
f2b-manage ban sshd IP  # IP manuell bannen
f2b-manage unban-all    # Alle IPs entbannen
f2b-manage logs         # Logs anzeigen
```

### Direkte Befehle

```bash
# Firewall-Status
sudo nft list ruleset
sudo iptables -L -n

# Fail2ban-Status
sudo fail2ban-client status
sudo fail2ban-client status sshd

# Service-Status
sudo systemctl status nftables
sudo systemctl status fail2ban
```

## 🔍 Verifizierung

### Automatischer Check

```bash
sudo ./check-firewall.sh
# oder
vps-manage check
```

### Manuelle Tests

```bash
# SSH Port testen
timeout 2 bash -c "echo >/dev/tcp/localhost/4848" && echo "✓ Port open" || echo "✗ Port blocked"

# Aktive Verbindungen
ss -tlnp | grep -E "4848|80|443"

# Gebannte IPs
sudo fail2ban-client status sshd
```

## 🚨 Troubleshooting

### SSH-Verbindung verloren?

1. **Warten**: Boot-Safety-Service aktiviert sich nach 5 Minuten
2. **Alternative Ports**: Versuchen Sie Port 22 UND 4848
3. **Notfall-Zugang**: VPS-Provider-Konsole verwenden

### Firewall-Reset (Notfall)

```bash
# Alle Regeln löschen
sudo iptables -F
sudo iptables -X
sudo iptables -P INPUT ACCEPT
sudo iptables -P FORWARD ACCEPT
sudo iptables -P OUTPUT ACCEPT
sudo nft flush ruleset
```

### IP entbannen

```bash
# Einzelne IP
sudo fail2ban-client set sshd unbanip <IP>

# Alle IPs
f2b-manage unban-all
```

## 📁 Wichtige Dateien

Nach der Installation:

- **Scripts**: `/opt/vps-config/`
- **Firewall-Config**: `/etc/nftables.conf`
- **Fail2ban-Config**: `/etc/fail2ban/jail.local`
- **SSH-Config**: `/etc/ssh/sshd_config`
- **Logs**: `/var/log/vps-setup-*.log`
- **Report**: `/root/vps-setup-report-*.txt`

## 🐳 Docker/Coolify Kompatibilität

Die Firewall-Konfiguration ist Docker-kompatibel:

- Verwendet iptables-nft Compatibility Layer
- Erhält Docker-Chains (DOCKER, DOCKER-USER)
- nftables mit niedrigerer Priorität als iptables
- Keine DROP-Policies die Docker blockieren würden

## 📊 Monitoring

### Installierte Tools

- **htop**: System-Ressourcen
- **iftop**: Netzwerk-Traffic
- **vnstat**: Bandbreiten-Statistik
- **nethogs**: Prozess-Netzwerk-Nutzung
- **fail2ban-client**: Security-Monitoring

### Log-Dateien

```bash
# Fail2ban Logs
tail -f /var/log/fail2ban.log

# SSH Logs
tail -f /var/log/auth.log

# Firewall Logs
journalctl -u nftables -f
```

## 🔐 Sicherheits-Features

- ✅ SSH auf nicht-standard Port (4848)
- ✅ Brute-Force-Schutz via fail2ban
- ✅ Automatische IP-Bans nach 5 Fehlversuchen
- ✅ DDoS-Schutz für SSH
- ✅ Port-Scan-Erkennung
- ✅ Firewall mit Default-Deny-Policy
- ✅ Boot-Safety-Service (Fallback)
- ✅ Duale Firewall-Layer (nftables + iptables)

## 📝 Lizenz

MIT License - siehe [LICENSE](LICENSE) Datei

## 🤝 Contributing

Pull Requests sind willkommen! Für größere Änderungen bitte erst ein Issue öffnen.

## ⚠️ Haftungsausschluss

Diese Scripts sind für Produktivumgebungen gedacht, aber verwenden Sie sie auf eigene Gefahr. Testen Sie immer erst in einer Entwicklungsumgebung.

## 📞 Support

Bei Problemen:

1. Check die Logs: `/var/log/vps-setup-*.log`
2. Nutze `vps-manage check` für Diagnose
3. Öffne ein [Issue](https://github.com/christiankriedemann/vps-config/issues)

---

**Version**: 1.0
**Getestet auf**: Debian 11/12/13, Ubuntu 20.04/22.04
**Autor**: Christian Kriedemann
**Repository**: [github.com/christiankriedemann/vps-config](https://github.com/christiankriedemann/vps-config)
