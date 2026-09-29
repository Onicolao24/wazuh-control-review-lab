# Wazuh Control Review Lab

This project is a small control review completed in an isolated home lab. I used Wazuh to test file integrity monitoring (FIM), investigate a controlled file change, review a real security configuration finding, apply one safe correction, and measure the result.

All test records are fictional. No real customer data, third-party accounts, or production systems were used.

## What I tested

| Control | Test | Verified result |
| --- | --- | --- |
| File integrity monitoring | Baseline two fictional client files, modify one file under change ID `LAB-CHG-001`, and review the Wazuh evidence | One Wazuh rule `550` modification alert with a content diff and different before/after SHA-256 hashes |
| Security configuration assessment | Review the Ubuntu CIS policy, correct check `35594`, and run a new scan | `/etc/crontab` changed from `0644` to `0600`; the check changed from `failed` to `passed` |

## Lab environment

- VMware NAT network: `192.168.150.0/24`
- Wazuh server: Ubuntu Server 24.04.4 LTS, Wazuh `4.14.7`
- Monitored endpoint: Kali Linux, Wazuh agent `001`, Wazuh `4.14.7`
- Wazuh manager, indexer, and dashboard were verified active before testing
- Fictional records were exposed to the endpoint through a dedicated VMware shared folder
- FIM ran on agent `001`; the SCA remediation was verified through the server's monitored local agent `000`

The existing Wazuh installation was preserved. I did not reinstall it or weaken the Windows host to create a finding.

## Measured outcome

| Metric | Result |
| --- | ---: |
| Baseline files | 2 |
| FIM events detected | 1 |
| FIM events investigated | 1 |
| SCA findings corrected | 1 |
| Failed SCA checks before | 118 |
| Failed SCA checks after | 117 |
| Passed SCA checks before | 119 |
| Passed SCA checks after | 120 |
| Documented follow-up items | 2 |

The overall SCA score stayed at `50` because Wazuh reported a whole-number score, even though the pass/fail counts improved by one.

## FIM investigation

The normal state contained two text files with fake client ID `FA-1001`. I changed `account_review_FA-1001.txt` from `Baseline approved` to `Follow-up required` and added change ticket `LAB-CHG-001`.

Wazuh recorded:

- Agent `001` (`kali-linux`)
- Rule `550`, level `7`: `Integrity checksum changed.`
- Event type `modified`
- The monitored path and event time
- File size change from `101` to `129` bytes
- SHA-256 before `66ac...e2fa` and after `d3b1...1faf`
- The exact text diff

The included baseline and post-change sample files reproduce both SHA-256 values. This proves that Wazuh observed a change to the monitored file and preserved useful investigation evidence. It does **not** prove the change was an attack, identify a person, or establish malicious intent. The investigation classified it as an authorized control test.

The VMware shared filesystem did not produce a demonstrated real-time notification. I requested a scheduled FIM scan, which detected the change. The mount also reported broad `rwxrwxrwx` permissions, so it is not a production access-control design. Those limitations are kept in the report instead of being hidden.

## SCA correction

Wazuh's Ubuntu CIS policy reported check `35594`, `Ensure permissions on /etc/crontab are configured`, as failed. The file was owned by `root:root` with mode `0644`. I preserved a backup, changed the mode to `0600`, restarted the Wazuh manager to run a new SCA scan, and verified the same check as passed.

The change reduces unnecessary read access to the system crontab. It does not resolve the other `117` failed checks; those remain candidates for risk-based review, not automatically confirmed vulnerabilities.

## Reproduce the metrics

The script uses only the Python standard library.

```bash
python3 scripts/generate_metrics.py
python3 -m unittest discover -s tests -v
```

Generated files:

- `reports/metrics.json`
- `reports/metrics-report.md`

The script cross-checks the FIM baseline hash against the alert's before-hash, verifies that the after-hash changed, joins the alert to the investigation log, and verifies the SCA failed-to-passed transition.

## Project documents

- [Executive summary](reports/executive-summary.md)
- [Generated metrics report](reports/metrics-report.md)
- [Technical control review](docs/control-review.md)
- [Lab inspection log](docs/lab-inspection.md)
- [One-minute interview pitch](docs/interview-pitch.md)
- [Resume description](docs/resume-description.md)
- [Evidence index](evidence/README.md)

## Repository layout

- `data/observed/`: sanitized Wazuh exports and investigation metadata
- `data/sample-client-records/`: fictional baseline and post-change file snapshots
- `docs/`: inspection notes, technical review, interview pitch, and internship alignment
- `evidence/`: configuration excerpts, evidence index, and filtered raw records
- `reports/`: generated metrics and the one-page executive summary
- `scripts/`: reproducible Python reporting code
- `tests/`: standard-library unit tests

## Why this relates to the internship

The project demonstrates four basic responsibilities I expect in a cybersecurity internship: identify a risk, improve a control, track evidence-based metrics, and explain a recommendation without overstating what the tools proved. See [`docs/internship-alignment.md`](docs/internship-alignment.md).

## References

- [Wazuh file integrity monitoring](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)
- [Wazuh SCA overview](https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/index.html)
- [Wazuh custom SCA policies](https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/creating-custom-policies.html)
