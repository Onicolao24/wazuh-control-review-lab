# Executive Summary

## Purpose

This project reviewed two security controls in an isolated Linux lab. It used only virtual machines and fictional test records. The goal was to test a control, investigate an observed issue, make a measured correction, and communicate the result without overstating the evidence.

## Results

File Integrity Monitoring was configured on Wazuh agent `001` for a folder containing two fictional records. After a baseline was captured, planned change `LAB-CHG-001` modified one file. A requested scheduled scan produced one Wazuh rule `550` alert with the file path, timestamp, size change, before and after SHA-256 hashes, and exact content diff. The event was investigated and matched to the authorized test. This proves that the tested configuration recorded the change; it does not prove an attack, malicious intent, or user attribution.

The Ubuntu Security Configuration Assessment identified check `35594`, concerning permissions on `/etc/crontab`, as failed. The file mode was changed from `0644` to `0600` while ownership remained `root:root`. A later assessment marked the same check passed. Policy counts changed from 119 passed and 118 failed to 120 passed and 117 failed. The 42 invalid checks were unchanged, and the displayed score remained 50. The remaining failed checks require individual review before they can be called vulnerabilities.

## Metrics

| Measure | Result |
| --- | ---: |
| Baseline files monitored | 2 |
| FIM events detected | 1 |
| Events investigated | 1 |
| Findings corrected and verified | 1 |
| Pending follow-up items | 2 |

The Python reporting script validates the baseline-to-alert hash chain, links the alert to its investigation, verifies the SCA before/after transition, and generates the metrics from exported data. This keeps detection, investigation, remediation, and pending work separate.

## Recommendation

Repeat the FIM test on a local endpoint directory to evaluate real-time notification without the VMware shared-filesystem limitation. Then triage the remaining SCA failures individually, prioritizing changes by risk and operational impact. This project demonstrates a repeatable approach to identifying risk, improving a control, measuring the result, and explaining recommendations to a non-technical stakeholder.
