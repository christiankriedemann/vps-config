#!/bin/bash

# Lynis Security Audit
sudo lynis audit system

# Rootkit-Check
sudo rkhunter --check

# Offene Ports prüfen
sudo netstat -tulpn
sudo ss -tulpn
