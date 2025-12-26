# auditD

This directory contains Auditd-related rules and configuration for Wazuh. The files here are intended to help detect and alert on important auditd events (process execution, file changes, syscall monitoring, SELinux/Audit policy violations, etc.) within hosts monitored by Wazuh.

## Contents
- README.md — this file
- rules/ — Wazuh rule files (local rules, decoders, or manager rules)
- decoders/ — custom decoders for auditd event formats (if present)
- examples/ — example auditd rules or configuration snippets

> Note: Adjust the paths below to match your Wazuh deployment layout (agent vs manager).

## Requirements
- Wazuh manager and/or agent (supported versions may vary)
- auditd enabled on monitored hosts

## Installation
1. Copy rule files to the Wazuh rules directory on the manager or agent. Common locations:
   - /var/ossec/etc/rules/local_rules.xml
   - /var/ossec/etc/rules/
2. Place decoders (if any) under:
   - /var/ossec/etc/decoders/
3. Restart the Wazuh manager/agent to apply changes:
   - sudo systemctl restart wazuh-manager
   - sudo systemctl restart wazuh-agent

If you manage rules centrally (via the manager), deploy the rule files to manager and ensure agents receive updated configurations.

## Testing
- Generate audit events on a test host (e.g., create/remove files, run monitored commands) and confirm alerts appear in the Wazuh dashboard or alerts log.
- Use `ausearch` or `auditctl` on the host to validate auditd events are generated.

## Best practices
- Test new rules in a staging environment before deploying to production.
- Keep rules as specific as possible to reduce false positives.
- Document any changes and their intended detections in this repo.

## Contributing
1. Open an issue describing the change or detection you want to add.
2. Submit a pull request with the rule/decoder files and a short description.
3. Include tests or example events when possible.

## License
Specify the repository license here, or consult the repository root for the license used.

---

If you'd like, I can:
- Customize this README with explicit installation commands for your environment,
- Create example rule and decoder templates in this directory,
- Or open a pull request with the README and sample files.
