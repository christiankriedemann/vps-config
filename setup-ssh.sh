#!/bin/bash

# Backup erstellen
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

# SSH-Port setzen
sed -i 's/^#*Port .*/Port 4848/' /etc/ssh/sshd_config

# Weitere Sicherheitseinstellungen
cat >> /etc/ssh/sshd_config << 'EOF'

# Security hardening
PermitRootLogin prohibit-password
PasswordAuthentication no
PubkeyAuthentication yes
PermitEmptyPasswords no
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
EOF

# SSH neustarten
systemctl restart sshd
