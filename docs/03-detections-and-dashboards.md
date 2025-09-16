# Detections and Dashboards

## Detection Use Cases

1.  **EICAR File Drop**
    -   Copy EICAR test file onto Ubuntu endpoint.
    -   Wazuh triggers malware detection rule.
2.  **SSH Brute Force**
    -   From Parrot OS, run Hydra brute force against Ubuntu:

        ``` bash
        hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.100.10
        ```

    -   Wazuh should detect repeated failed login attempts.
3.  **Privilege Escalation**
    -   Simulate creation of SUID file:

        ``` bash
        sudo chmod u+s /bin/bash
        ```

    -   Wazuh rule alerts on suspicious file changes.

## Dashboards

-   **Agent Status Dashboard**: shows connected/disconnected agents.
-   **Detection Alerts**: timeline of triggered rules.
-   **Patch Compliance**: osquery output visualized in Wazuh dashboards.

## Steps to Build Dashboards

1.  Log into Wazuh Dashboard (`https://<wazuh-ip>:5601`).
2.  Navigate to "Discover" to search logs by index.
3.  Save search queries for detections.
4.  Build visualizations and group into dashboards.

------------------------------------------------------------------------
