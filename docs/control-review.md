# Control Review

## Control 1: File Integrity Monitoring

### Objective

Test whether Wazuh records a controlled content change to fictional client files on a monitored endpoint.

### Method

1. Confirmed that Wazuh agent `001` was active on `kali-linux`.
2. Created two fictional text records under `/mnt/hgfs/codex_lab/client_records`.
3. Added the path to the centrally managed Wazuh FIM configuration with checksums and `report_changes` enabled.
4. Captured the baseline inventory and hashes.
5. Performed the planned change `LAB-CHG-001` to `account_review_FA-1001.txt`.
6. Requested a scheduled syscheck scan, located the resulting alert, and documented an investigation.

### Observed result

Wazuh rule `550`, level `7`, recorded one modified-file event at `2026-09-29T01:31:43.693+0000`. The record contains the monitored path, a size change from 101 to 129 bytes, different before and after SHA-256 values, and the exact text diff. Investigation `INV-FIM-001` matched those details to the authorized test change and closed the event as an authorized control test.

### What the evidence proves

The evidence shows that Wazuh observed and recorded a content change to the monitored file. It also provides enough detail to compare the alert with the planned test.

### What the evidence does not prove

The alert alone does not establish malicious intent, identify the person who made the change, or prove that an attack occurred. This was a simulation. Because the path was on a VMware shared filesystem, a real-time notification was not demonstrated; the change was detected by a requested scheduled scan. The mount also reported broad `rwxrwxrwx` permissions, so this lab path should not be treated as a model for protecting sensitive production records. This test evaluated change detection, not production access control.

## Control 2: Security Configuration Assessment

### Objective

Select one real, low-risk SCA finding from the lab, correct it, and verify the result without weakening the host.

This assessment ran through the Wazuh server's monitored local agent (`000`). The separate Kali endpoint (`001`) was used for the FIM test.

### Method

1. Reviewed the Ubuntu 24.04 CIS SCA results on the Wazuh server.
2. Selected check `35594`, `Ensure permissions on /etc/crontab are configured.`
3. Verified the original state: mode `0644`, owner `root:root`, result `failed`.
4. Preserved a backup and changed the mode to `0600`; ownership remained `root:root`.
5. Triggered a new assessment and verified that the same check passed.

### Observed result

The selected check moved from failed to passed. At the policy-summary level, passed checks increased from 119 to 120 and failed checks decreased from 118 to 117. The displayed score remained 50 because of whole-number scoring or rounding. The 42 invalid checks were unchanged.

### Risk interpretation

Restricting `/etc/crontab` reduces unnecessary read access to a system scheduling configuration file. This test proves the state and result of one specific check. The other failed checks have not been validated as vulnerabilities and remain pending triage.

### Rollback

The documented rollback is `chmod 0644 /etc/crontab`. It was not needed because the server and Wazuh manager remained operational after the correction.
