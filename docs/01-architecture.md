# Lab Architecture

## Overview

The lab is designed as a fully isolated environment running on **Oracle
VirtualBox**. All virtual machines are segmented via a **pfSense
firewall** to simulate a secure enterprise network. Logging, monitoring,
and detections are centralized in **Wazuh SIEM**.

## Components

-   **pfSense Firewall**
    -   Acts as the gateway and segmentation device for the lab.
    -   Provides isolation from the host and internet.
    -   Manages firewall rules and routing.
-   **Wazuh Manager**
    -   Centralized SIEM for log collection and security event
        monitoring.
    -   Receives logs from all endpoints.
    -   Provides dashboards and detection rules.
-   **Endpoints**
    -   Ubuntu Server → General-purpose endpoint with auditd and
        osquery.
    -   Parrot OS → Attacker simulation VM.
    -   Metasploitable2 → Vulnerable system for exploitation and
        detection testing.

## Network Topology

``` mermaid
graph TD
  pfSense[pfSense Firewall]
  wazuh[Wazuh Manager]
  ubuntu[Ubuntu Endpoint]
  parrot[Parrot OS]
  meta[Metasploitable2]

  pfSense --> wazuh
  pfSense --> ubuntu
  pfSense --> parrot
  pfSense --> meta
```

------------------------------------------------------------------------
