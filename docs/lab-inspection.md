# Lab Inspection Log

Inspection completed: 2026-09-29 UTC

## Scope and safety

- Testing was limited to isolated local virtual machines and fictional client data.
- No real customer accounts, documents, or third-party systems were used.
- The existing Wazuh installation was inspected and preserved; it was not reinstalled.

## Verified environment

| Component | Verified state |
| --- | --- |
| Hypervisor | VMware Workstation Pro |
| Lab network | VMnet8 NAT, `192.168.150.0/24` |
| Wazuh server | Ubuntu Server 24.04.4 LTS, `wazuhserver`, `192.168.150.129` |
| Wazuh version | 4.14.7 |
| Wazuh services | Manager, indexer, and dashboard active and enabled |
| Dashboard | Reachable over HTTPS from the Windows host |
| Local manager agent | ID `000`, `wazuhserver`, Active/Local |
| Test endpoint | ID `001`, `kali-linux`, `192.168.150.128`, Active, Wazuh 4.14.7 |

The Kali endpoint is stored in a VMware guest whose inventory name is `Debian 13.x 64-bit`. The operating system and Wazuh agent identify it as `kali-linux`.

## Control paths

- FIM test data: `/mnt/hgfs/codex_lab/client_records`
- Central agent configuration: `/var/ossec/etc/shared/default/agent.conf`
- SCA policy used for remediation: `cis_ubuntu24-04`
- Remediated server file: `/etc/crontab`

## Inspection conclusion

The existing Wazuh deployment was healthy enough to conduct both control tests. Agent `001` provided endpoint FIM evidence, and the manager's local agent provided the Ubuntu SCA result. Raw command evidence is retained under `evidence/raw/`.
