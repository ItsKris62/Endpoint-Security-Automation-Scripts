#!/bin/bash
# software_inventory.sh
# Script to capture installed packages for inventory purposes.

LOG_FILE="/var/log/endpoint-automation/software_inventory.log"
mkdir -p $(dirname $LOG_FILE)

echo "[*] Capturing installed software inventory..."
date > $LOG_FILE
dpkg-query -W -f='${binary:Package} ${Version}\n' >> $LOG_FILE

echo "[+] Software inventory captured in $LOG_FILE."
