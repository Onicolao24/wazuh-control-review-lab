# Evidence Index

## Reproducible configuration

| File | Purpose |
| --- | --- |
| `fim-agent-config.xml` | Centrally managed FIM configuration used for the endpoint path |
| `mount-validation-policy.yml` | File-only SCA check used to confirm that the shared path was visible to the endpoint agent |

## Raw command evidence

| File | Purpose |
| --- | --- |
| `raw/codex_wazuh_inspection.txt` | Server version, service state, and agent inventory inspection |
| `raw/codex_fim_config_result.txt` | FIM configuration validation evidence |
| `raw/codex_shared_fim_config_result.txt` | Central configuration application evidence |
| `raw/codex_mount_check_result.txt` | Endpoint visibility check for the monitored shared path |
| `raw/codex_sca_remediation_result.txt` | SCA check before/after result and the applied change |
| `raw/codex_reporting_validation.txt` | Python version, generator result, unit-test result, and final Wazuh health check |

## Structured observed data

The files under `data/observed/` are the machine-readable inputs to the metrics script. They contain the FIM baseline, controlled-change alert, SCA before/after state, and investigation log. No credentials or real client data are included.

The raw files provide supporting lab output; the structured files are the source of the reported metrics. A reader should use both when reviewing the claims.
