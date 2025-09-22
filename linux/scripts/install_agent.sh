#!/bin/bash
# install_agent.sh
# This script installs and configures the Wazuh agent on a Linux endpoint.

# Exit on error
set -e

# Variables - update these for your environment
WAZUH_MANAGER_IP="192.168.100.2"

echo "[*] Installing Wazuh agent..."
curl -sO https://packages.wazuh.com/4.8/wazuh-agent.sh
sudo bash wazuh-agent.sh

echo "[*] Configuring agent to connect to manager at $WAZUH_MANAGER_IP..."
sudo sed -i "s/MANAGER_IP/$WAZUH_MANAGER_IP/" /var/ossec/etc/ossec.conf

echo "[*] Starting Wazuh agent service..."
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent

echo "[+] Wazuh agent installation complete."
