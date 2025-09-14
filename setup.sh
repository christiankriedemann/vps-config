#!/bin/bash

sudo apt update
sudo apt upgrade -y
sudo apt dist-upgrade -y
sudo apt autoremove -y

# Systemüberwachung
sudo apt install -y htop iotop nethogs

# Sicherheits-Audit
sudo apt install -y lynis rkhunter

# Log-Analyse
sudo apt install -y logwatch

# Unattended Upgrades
sudo apt install -y unattended-upgrades apt-listchanges

sudo dpkg-reconfigure -plow unattended-upgrades
