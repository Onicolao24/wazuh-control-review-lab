# Internship Alignment

This project connects to four common responsibilities in a cybersecurity internship.

## Identify risk

I reviewed a real SCA result from the lab and selected a specific configuration issue instead of treating every failed check as a confirmed vulnerability. The `/etc/crontab` permission finding had a clear expected state, a limited change, and a documented rollback.

## Improve controls

I configured FIM for fictional client records and corrected one SCA finding. Both changes were validated using evidence from the same Wazuh deployment rather than assumed to work after configuration.

## Track metrics

The Python script separates events detected, events investigated, findings corrected, and pending items. It also validates the relationships among the baseline, alert, investigation, and before/after SCA data so the report can be reproduced.

## Communicate recommendations

The control review distinguishes what the evidence proves from what it does not prove. It explains that the FIM alert detected a change but did not prove an attack, and it leaves the remaining SCA checks pending until they can be reviewed individually.
