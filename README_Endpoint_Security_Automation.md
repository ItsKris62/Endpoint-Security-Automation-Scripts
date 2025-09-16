# Endpoint Security Automation Scripts

This project provides a collection of cross-platform automation scripts
for **endpoint security monitoring and compliance** in an isolated
cybersecurity lab. It is designed to streamline the setup and management
of security agents, enforce patch compliance, and ensure centralized
visibility of endpoint activities via **Wazuh SIEM**. The lab
environment is fully virtualized on **Oracle VirtualBox** and segmented
with a **pfSense firewall**.

##  Project Overview

The main goal of this project is to automate the repetitive but critical
tasks of endpoint security management. By combining Bash scripts with
open-source monitoring tools, endpoints become easier to onboard,
maintain, and monitor.

The project focuses on: - Automating **agent deployment and health
checks** across Linux endpoints. - Integrating **auditd** and
**osquery** for enhanced telemetry collection. - Automating **patch
compliance checks** and **software inventory reports**. - Forwarding
custom logs to **Wazuh SIEM** for centralized analysis. - Creating
detection workflows for common attacker behaviors (EICAR malware test,
SSH brute force, privilege escalation attempts).

##  Lab Environment

-   **Virtualization**: Oracle VirtualBox
-   **Firewall/Segmentation**: pfSense (isolated LabNet)
-   **SIEM**: Wazuh Manager
-   **Endpoints**:
    -   Ubuntu Server
    -   Parrot OS (attacker simulation)
    -   Metasploitable2 (intentionally vulnerable)
    -   (Other Linux variants supported)

The pfSense firewall isolates the lab from the host and internet,
ensuring safe experimentation.

##  Repository Structure

    endpoint-security-automation/
      README.md
      /linux/
        install_agent.sh
        setup_auditd.sh
        osquery.conf
        cronjobs/
      /wazuh/
        custom-rules/
        decoders/
        alerts/
      /detection-tests/
        eicar/
        ssh-bruteforce/
        privilege-escalation/
      /docs/
        01-architecture.md
        02-build-and-config.md
        03-detections-and-dashboards.md
        04-ir-runbook.md
        05-troubleshooting.md
        imgs/

##  Features

-   **Agent Automation**: Deploy and manage Wazuh agents on Linux
    endpoints.
-   **Telemetry Collection**: Enable auditd + osquery for process, file
    integrity, and inventory monitoring.
-   **Patch & Inventory**: Automate system updates and generate
    compliance reports.
-   **Centralized Logging**: Ship JSON logs into Wazuh for correlation
    and alerting.
-   **Detection Rules**: Predefined detection scripts for malware
    simulation, SSH brute force, and privilege misuse.
-   **Dashboards**: Visualize endpoint compliance and alerts in
    Wazuh/OpenSearch dashboards.

##  Getting Started

1.  Clone the repository:

    ``` bash
    git clone https://github.com/ItsKris62/Endpoint-Security-Automation.git
    cd Endpoint-Security-Automation
    ```

2.  Configure your environment variables in `linux/install_agent.sh`.

3.  Run scripts on each endpoint to install and configure the agent:

    ``` bash
    sudo bash linux/install_agent.sh
    ```

4.  Validate agent connectivity in Wazuh dashboard.

5.  Deploy detection tests from `/detection-tests` and confirm alerts
    fire in Wazuh.

##  Example Detection Use Cases

-   **EICAR File Drop** → triggers malware detection rules.\
-   **SSH Brute Force** → logs repeated failed logins and triggers
    alert.\
-   **Privilege Escalation Attempt** → monitors unauthorized use of SUID
    binaries.

##  Documentation & Screenshots

All project documentation is under `/docs`, with step-by-step setup
guides and runbooks. Screenshots are included under `/docs/imgs` to
show: - Agent installation outputs - pfSense rules - Wazuh dashboards -
Triggered alerts

Naming convention: `02-build-ubuntu-agent-install-01.png`

##  Future Enhancements

-   Add Ansible playbooks for bulk agent deployment.
-   Integrate Slack/email alerting into Wazuh rules.
-   Extend detection coverage with advanced osquery packs.

##  License

This project is released under the MIT License.

------------------------------------------------------------------------

**Author:** Christopher Modicai Rateng\
**Portfolio:** <https://christopherrateng.netlify.app>\
**LinkedIn:** <https://www.linkedin.com/in/christopher-rateng>
