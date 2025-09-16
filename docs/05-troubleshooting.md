# Troubleshooting Guide

## Common Issues

### 1. Agent Not Connecting to Wazuh Manager

-   Check agent config at `/var/ossec/etc/ossec.conf`.
-   Ensure correct manager IP set.
-   Run `systemctl status wazuh-agent`.

### 2. pfSense Blocking Logs

-   Review pfSense firewall rules under LAN interface.
-   Ensure ports 1514 (TCP/UDP) and 55000 (TCP) are allowed.

### 3. Time Drift Between VMs

-   Sync VM clocks using VirtualBox Guest Additions or NTP.

### 4. Dashboard Not Loading

-   Restart Wazuh services:

    ``` bash
    sudo systemctl restart wazuh-manager
    sudo systemctl restart wazuh-dashboard
    ```

### 5. Decoder or Rule Not Working

-   Validate custom rule syntax.
-   Check logs: `/var/ossec/logs/ossec.log`.

------------------------------------------------------------------------
