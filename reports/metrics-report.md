# Control Review Metrics

Evidence captured through: `2026-09-29T01:36:26.241274+00:00`

## Measured results

| Category | Metric | Value |
| --- | --- | ---: |
| FIM | Baseline files | 2 |
| FIM | Events detected | 1 |
| FIM | Events investigated | 1 |
| FIM | Investigation coverage | 100.0% |
| SCA | Findings corrected | 1 |
| SCA | Failed checks before | 118 |
| SCA | Failed checks after | 117 |
| SCA | Passed checks before | 119 |
| SCA | Passed checks after | 120 |
| Pending | Failed SCA checks requiring triage | 117 |
| Pending | Documented follow-up items | 2 |
| Tracked separately | Invalid or not-evaluated SCA checks | 42 |

## Evidence checks

- The FIM before-hash matched the baseline for 1 modified file.
- Controlled change `LAB-CHG-001` produced 1 modification alert.
- SCA check `35594` changed from failed to passed: `True`.
- The whole-number SCA score remained unchanged even though one failed check moved to passed.

## Interpretation limits

- A FIM alert proves that Wazuh observed a change to the monitored file and recorded its attributes. It does not prove malicious intent or identify a person unless separate attribution evidence is collected.
- The VMware shared filesystem required a requested scheduled scan for this event. Real-time notification was not demonstrated.
- Failed SCA checks are review candidates, not automatically confirmed vulnerabilities. Each remaining item needs context and risk review.
