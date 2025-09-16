# Build and Configuration Guide

## Prerequisites

-   Oracle VirtualBox installed on host machine.
-   pfSense ISO and Linux ISOs available.
-   At least 8GB RAM and 4 vCPUs recommended.

## Step 1: Deploy pfSense

1.  Create pfSense VM in VirtualBox.
2.  Assign two NICs: one for WAN (host-only) and one for LAN (internal
    network `LabNet`).
3.  Set LAN IP as `192.168.100.1`.

## Step 2: Deploy Wazuh Manager

1.  Create Ubuntu VM (2 vCPUs, 4GB RAM).

2.  Install Wazuh Manager using installation script:

    ``` bash
    curl -sO https://packages.wazuh.com/4.8/wazuh-install.sh
    sudo bash wazuh-install.sh -a
    ```

3.  Verify dashboard is accessible via `https://<wazuh-ip>:5601`.

## Step 3: Deploy Endpoints

### Ubuntu Endpoint

1.  Create Ubuntu VM (2 vCPUs, 2GB RAM).

2.  Install Wazuh agent:

    ``` bash
    curl -sO https://packages.wazuh.com/4.8/wazuh-agent.sh
    sudo bash wazuh-agent.sh
    ```

3.  Configure agent to connect to Wazuh Manager IP.

### Parrot OS & Metasploitable2

-   Deploy normally and install Wazuh agent on Parrot OS.
-   Skip Wazuh agent on Metasploitable2 (remains as vulnerable host).

## Step 4: Configure pfSense Firewall Rules

-   Allow traffic between endpoints and Wazuh Manager on ports `1514`
    (agent), `55000` (API).
-   Block internet access for lab VMs.

------------------------------------------------------------------------
