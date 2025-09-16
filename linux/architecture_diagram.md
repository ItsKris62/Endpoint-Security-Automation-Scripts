
```mermaid
graph TD
  pfSense[pfSense Firewall]
  wazuh[Wazuh Manager]
  ubuntu[Ubuntu Endpoint]
  parrot[Parrot OS (Attacker)]
  meta[Metasploitable2 (Vulnerable Host)]

  pfSense --> wazuh
  pfSense --> ubuntu
  pfSense --> parrot
  pfSense --> meta

  ubuntu -->|Wazuh Agent Logs| wazuh
  parrot -->|Wazuh Agent Logs| wazuh
```
