# Incident Response Runbook

## Daily Checks (≤10 minutes)

1.  Confirm all agents are online in Wazuh Dashboard.
2.  Review last 24 hours of alerts.
3.  Verify no ingestion or parsing errors.

## Triage Workflow

1.  **Identify**: Alert triggered in Wazuh Dashboard.
2.  **Investigate**: Correlate with logs from endpoint.
3.  **Contain**: Isolate affected VM (shut down interface in
    VirtualBox).
4.  **Eradicate**: Remove malicious process or file.
5.  **Recover**: Re-enable endpoint and validate health.

## Example: SSH Brute Force

-   Alert fires for multiple failed logins.
-   Check source IP (should be Parrot OS).
-   Contain → block IP via pfSense rule.
-   Document in runbook with screenshot.

------------------------------------------------------------------------
