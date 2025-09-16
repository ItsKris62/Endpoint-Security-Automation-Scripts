#!/bin/bash
# patch_compliance.sh
# Script to check for available security updates on Ubuntu/Debian systems.

echo "[*] Checking for available updates..."
sudo apt update -qq

echo "[*] Listing security updates..."
apt list --upgradable 2>/dev/null | grep -i security

# Output results to log file for Wazuh ingestion
LOG_FILE="/var/log/endpoint-automation/patch_compliance.log"
mkdir -p $(dirname $LOG_FILE)
date >> $LOG_FILE
apt list --upgradable 2>/dev/null | grep -i security >> $LOG_FILE

echo "[+] Patch compliance check complete. Results saved to $LOG_FILE."
