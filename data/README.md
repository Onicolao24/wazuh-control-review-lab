# Data provenance

`observed/` contains sanitized exports from the isolated lab. The records use only fictional client identifiers and private lab addresses. No credentials, tokens, SSH keys, or personal client data are included.

`sample-client-records/` contains the two fictional files in their baseline state and after controlled change `LAB-CHG-001`. These copies make the hash and diff evidence reproducible without access to the VM.

The phrase `Advisory simulation` remains inside one sample because it was part of the tested file content. Rewording that evidence after collection would change its SHA-256 and break the demonstrated baseline-to-alert hash chain; it is not part of the current project title or scope.

The metrics script reads four files:

- `codex_fim_baseline.json`: two-file FIM baseline from agent `001`.
- `codex_fim_change_alerts.json`: alert evidence for controlled change `LAB-CHG-001`.
- `codex_sca_before_after.json`: one SCA check before and after remediation.
- `investigation_log.json`: the student's review decision and pending follow-ups.

The first three files were exported from Wazuh. The investigation log is a small analyst-authored record that connects the exported alert to the review conclusion.

The `current_inventory` object in the FIM alert export is the inventory-query response returned at collection time. It still contained the earlier baseline record, so it is preserved for transparency but is not treated as post-change state. The metrics script instead validates the alert's `sha256_before` against the separately captured baseline and requires a different, non-empty `sha256_after`.
