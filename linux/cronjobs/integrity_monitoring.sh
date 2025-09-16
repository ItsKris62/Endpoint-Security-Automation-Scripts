#!/bin/bash
# integrity_monitoring.sh
# Script to monitor changes in critical system files.

WATCHED_DIRS="/etc /bin /sbin /usr/bin /usr/sbin"
LOG_FILE="/var/log/endpoint-automation/integrity_monitoring.log"

mkdir -p $(dirname $LOG_FILE)

echo "[*] Running integrity check on $WATCHED_DIRS..."
date >> $LOG_FILE
# Generate file checksums
for DIR in $WATCHED_DIRS; do
  find $DIR -type f -exec sha256sum {} \; >> $LOG_FILE
done

echo "[+] Integrity monitoring data saved to $LOG_FILE."
