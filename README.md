# VPS Server Setup - Debian V2

Automatisierte Sicherheitskonfiguration für Debian VPS Server mit intelligenter Package-Verwaltung, Firewall, Fail2ban, Kernel-Hardening und automatischen Updates.

## 🚀 Schnellstart (One-Liner Installation)

```bash
# Komplette automatische Installation mit einem Befehl:
curl -sSL https://raw.githubusercontent.com/christiankriedemann/vps-config/main/setup.sh | sudo bash

# Alternative mit wget:
wget -qO- https://raw.githubusercontent.com/christiankriedemann/vps-config/main/setup.sh | sudo bash
```

### Was macht das Setup?

- ✅ Vollständiges System-Update
- ✅ **Intelligente Package-Installation** (keine Duplikate dank Session-Tracking)
- ✅ Firewall-Konfiguration (nftables + iptables Dual-Stack)
- ✅ Fail2ban Setup mit Brute-Force-Schutz
- ✅ SSH-Härtung auf Port 4848
- ✅ **Kernel Security Hardening** (60+ Sicherheitsparameter)
- ✅ **Automatische Sicherheitsupdates** (unattended-upgrades)
- ✅ Monitoring-Tools Installation
- ✅ Automatische Verifizierung

## 🆕 Version 2 Features

### Gemeinsame Library (`lib/common.sh`)

- **Session-Tracking**: Verhindert doppelte Package-Installationen und Service-Konfigurationen
- **Intelligente Functions**: Automatische Erkennung von SSH-Port, Firewall-Backend, etc.
- **Fallback-Mechanismen**: Funktioniert auch bei Netzwerkproblemen
- **Zentrale Verwaltung**: Alle Backups, Logs und Configs an einem Ort

### Neue Security Features

- **Kernel Hardening**: SYN-Flood-Schutz, IP-Spoofing-Schutz, ASLR, und mehr
- **Auto-Updates**: Tägliche Sicherheitsupdates mit automatischem Reboot (2:00 Uhr)
- **Erweiterte Überwachung**: Mehr Monitoring-Tools und besseres Logging

## 📋 Voraussetzungen

- Debian (11/12/13) oder Ubuntu (20.04/22.04)
- Root oder sudo Zugang
- Mindestens 512MB RAM
- Aktive Internetverbindung

## 🛠️ Installierte Komponenten

### Sicherheits-Stack

- **Firewall**: nftables + iptables (Dual-Stack für Docker)
- **IPS**: fail2ban mit angepassten Regeln
- **Kernel**: Gehärtete Sysctl-Parameter
- **Updates**: unattended-upgrades + needrestart
- **SSH**: Port 4848 mit Hardening

### Tools & Monitoring

- System: htop, iotop, sysstat
- Netzwerk: iftop, nethogs, vnstat
- Security: aide, rkhunter, auditd
- Utilities: screen, tmux, vim, jq

## 📦 Manuelle Installation

```bash
# Repository klonen
git clone https://github.com/christiankriedemann/vps-config.git
cd vps-config
chmod +x *.sh

# Scripts einzeln ausführen (REIHENFOLGE WICHTIG!)
sudo ./setup-firewall.sh         # Zuerst Firewall
sudo ./setup-fail2ban.sh         # Dann Fail2ban
sudo ./setup-kernel-hardening.sh # Optional: Kernel-Härtung
sudo ./setup-auto-updates.sh     # Optional: Auto-Updates
sudo ./check-firewall.sh         # Verifizierung
```

## 🔧 Management-Befehle

### Haupt-Management-Tool

```bash
vps-manage check        # Kompletter Security-Check
vps-manage firewall     # Firewall-Regeln anzeigen
vps-manage fail2ban     # Fail2ban Status
vps-manage ssh-test     # SSH Port 4848 testen
vps-manage updates      # System-Updates prüfen
vps-manage kernel       # Kernel-Security-Parameter
vps-manage services     # Security-Services Status
vps-manage logs         # Security-Logs anzeigen
vps-manage update       # VPS-Config aktualisieren
```

### Fail2ban Management

```bash
f2b-manage status       # Alle Jails anzeigen
f2b-manage stats        # Ban-Statistiken
f2b-manage ban sshd IP  # IP manuell bannen
f2b-manage unban-all    # Alle IPs entbannen
```

### Update Management

```bash
check-updates           # Verfügbare Updates prüfen
update-manage status    # Auto-Update Status
update-manage logs      # Update-Historie
update-manage test      # Dry-Run Test
```

## 📁 Wichtige Dateien & Verzeichnisse

### Konfiguration

- `/opt/vps-config/` - Alle Setup-Scripts
- `/opt/vps-config/lib/common.sh` - Gemeinsame Library
- `/etc/nftables.conf` - Firewall-Regeln
- `/etc/fail2ban/jail.local` - Fail2ban-Config
- `/etc/sysctl.d/99-security-hardening.conf` - Kernel-Parameter
- `/etc/apt/apt.conf.d/50unattended-upgrades` - Auto-Updates

### Verwaltung

- `/root/vps-backups/` - Zentrale Backup-Location
- `/var/log/vps-setup/` - Setup-Logs
- `/var/cache/vps-setup/` - Session-Tracking-Daten
- `/root/vps-setup-report-*.txt` - Setup-Reports

## 🔍 Verifizierung

```bash
# Automatischer Security-Check
vps-manage check

# Manuelle Tests
vps-manage ssh-test     # SSH-Port
vps-manage services     # Service-Status
vps-manage kernel       # Kernel-Parameter

# Ports prüfen
ss -tlnp | grep -E "4848|80|443"

# Firewall-Regeln
nft list ruleset
iptables -L -n
```

## 🚨 Troubleshooting

### SSH-Zugang verloren

1. **Warten**: Boot-Safety-Service (5 Minuten)
2. **Alternative Ports**: Versuche 22 und 4848
3. **VPS-Console**: Provider-Konsole nutzen

### Notfall-Reset

```bash
# Firewall komplett öffnen
iptables -F && iptables -P INPUT ACCEPT
nft flush ruleset

# Fail2ban stoppen
systemctl stop fail2ban
f2b-manage unban-all

# SSH auf Standard zurück
sed -i 's/Port 4848/Port 22/' /etc/ssh/sshd_config
systemctl restart sshd
```

### Session-Tracking zurücksetzen

```bash
# Bei Problemen mit doppelten Installationen
rm -f /var/cache/vps-setup/*.list
```

## 🐳 Docker/Coolify Kompatibilität

Die Konfiguration ist vollständig Docker-kompatibel:

- Dual-Stack Firewall (nftables + iptables)
- Docker-Chains werden erhalten
- Keine blockierenden DROP-Policies
- Container-Netzwerk funktioniert

## 🔐 Sicherheits-Features

### Netzwerk-Sicherheit

- ✅ Firewall mit Default-Deny
- ✅ Fail2ban Brute-Force-Schutz
- ✅ SSH auf Custom-Port (4848)
- ✅ Port-Scan-Erkennung

### System-Härtung

- ✅ Kernel-Parameter gehärtet
- ✅ ASLR aktiviert
- ✅ SYN-Flood-Schutz
- ✅ IP-Spoofing-Schutz
- ✅ Core-Dumps deaktiviert

### Automatisierung

- ✅ Tägliche Security-Updates
- ✅ Automatische Service-Neustarts
- ✅ Reboot bei Bedarf (2:00 Uhr)
- ✅ Update-Benachrichtigungen

## 📊 Performance-Optimierungen

- **Session-Tracking**: Keine doppelten apt-install Aufrufe
- **Intelligente Installation**: Skip bereits installierter Pakete
- **Parallel-Verarbeitung**: Mehrere Operationen gleichzeitig
- **Cache-Nutzung**: Wiederverwendung von Ergebnissen

## 🆘 Support

Bei Problemen:

1. Logs prüfen: `/var/log/vps-setup/`
2. Diagnose: `vps-manage check`
3. GitHub Issue: [github.com/christiankriedemann/vps-config/issues](https://github.com/christiankriedemann/vps-config/issues)

## 📝 Changelog

### Version 2.0 (2024)

- Gemeinsame Library für alle Scripts
- Session-Tracking gegen Duplikate
- Kernel-Hardening Script
- Auto-Updates Script
- Erweiterte Management-Tools
- Bessere Fehlerbehandlung

### Version 1.0 (2024)

- Initial Release
- Firewall + Fail2ban
- Basic SSH Hardening

## ⚖️ Lizenz

MIT License - siehe [LICENSE](LICENSE)

## 👨‍💻 Autor

**Christian Kriedemann**
GitHub: [github.com/christiankriedemann](https://github.com/christiankriedemann)

---

**Version**: 2.0
**Getestet auf**: Debian 11/12/13, Ubuntu 20.04/22.04
**Letztes Update**: 2024
