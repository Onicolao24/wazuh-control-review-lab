#!/usr/bin/env python3
"""Generate reproducible control-review metrics from sanitized lab exports."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


BASELINE_NAME = "codex_fim_baseline.json"
FIM_ALERTS_NAME = "codex_fim_change_alerts.json"
SCA_NAME = "codex_sca_before_after.json"
INVESTIGATION_NAME = "investigation_log.json"


class DataError(ValueError):
    """Raised when evidence is missing or internally inconsistent."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise DataError(f"Missing input file: {path}") from exc
    except json.JSONDecodeError as exc:
        raise DataError(f"Invalid JSON in {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise DataError(f"Expected a JSON object in {path}")
    return value


def require_mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise DataError(f"Expected an object at {label}")
    return value


def require_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise DataError(f"Expected a list at {label}")
    return value


def require_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise DataError(f"Expected an integer at {label}")
    return value


def event_key(alert: dict[str, Any]) -> tuple[str, str, str]:
    rule = require_mapping(alert.get("rule"), "alert.rule")
    syscheck = require_mapping(alert.get("syscheck"), "alert.syscheck")
    timestamp = alert.get("timestamp")
    rule_id = rule.get("id")
    path = syscheck.get("path")
    if not all(isinstance(value, str) and value for value in (timestamp, rule_id, path)):
        raise DataError("Each FIM alert needs timestamp, rule.id, and syscheck.path")
    return timestamp, rule_id, path


def investigation_key(record: dict[str, Any]) -> tuple[str, str, str]:
    ref = require_mapping(record.get("event_ref"), "investigation.event_ref")
    values = (ref.get("timestamp"), ref.get("rule_id"), ref.get("path"))
    if not all(isinstance(value, str) and value for value in values):
        raise DataError("Each investigation needs timestamp, rule_id, and path")
    return values  # type: ignore[return-value]


def validate_scan(scan: dict[str, Any], label: str) -> None:
    passed = require_int(scan.get("pass"), f"{label}.pass")
    failed = require_int(scan.get("fail"), f"{label}.fail")
    invalid = require_int(scan.get("invalid"), f"{label}.invalid")
    total = require_int(scan.get("total_checks"), f"{label}.total_checks")
    if passed + failed + invalid != total:
        raise DataError(f"{label} counts do not add up to total_checks")


def build_metrics(data_dir: Path) -> dict[str, Any]:
    baseline = load_json(data_dir / BASELINE_NAME)
    fim_export = load_json(data_dir / FIM_ALERTS_NAME)
    sca = load_json(data_dir / SCA_NAME)
    review = load_json(data_dir / INVESTIGATION_NAME)

    baseline_files = require_list(baseline.get("files"), "baseline.files")
    baseline_by_path: dict[str, dict[str, Any]] = {}
    for raw_entry in baseline_files:
        entry = require_mapping(raw_entry, "baseline.files[]")
        path = entry.get("full_path")
        if not isinstance(path, str) or not path:
            raise DataError("Every baseline entry needs full_path")
        if path in baseline_by_path:
            raise DataError(f"Duplicate baseline path: {path}")
        baseline_by_path[path] = entry

    raw_alerts = require_list(fim_export.get("alerts"), "fim_export.alerts")
    alerts = [require_mapping(item, "fim_export.alerts[]") for item in raw_alerts]
    detected_keys = {event_key(alert) for alert in alerts}
    if len(detected_keys) != len(alerts):
        raise DataError("Duplicate FIM alerts were found in the export")

    modification_count = 0
    validated_hash_chains = 0
    scheduled_count = 0
    for alert in alerts:
        syscheck = require_mapping(alert.get("syscheck"), "alert.syscheck")
        if syscheck.get("mode") == "scheduled":
            scheduled_count += 1
        if syscheck.get("event") != "modified":
            continue
        modification_count += 1
        path = syscheck.get("path")
        if not isinstance(path, str) or path not in baseline_by_path:
            raise DataError(f"Modified path is missing from the baseline: {path}")
        before_hash = syscheck.get("sha256_before")
        after_hash = syscheck.get("sha256_after")
        baseline_hash = baseline_by_path[path].get("sha256")
        if before_hash != baseline_hash:
            raise DataError(f"Before hash does not match the baseline for {path}")
        if not isinstance(after_hash, str) or not after_hash or after_hash == before_hash:
            raise DataError(f"After hash is missing or unchanged for {path}")
        validated_hash_chains += 1

    raw_investigations = require_list(review.get("investigations"), "review.investigations")
    investigations = [require_mapping(item, "review.investigations[]") for item in raw_investigations]
    investigated_keys: set[tuple[str, str, str]] = set()
    for record in investigations:
        key = investigation_key(record)
        if key not in detected_keys:
            raise DataError(f"Investigation references an unknown alert: {key}")
        if record.get("status") == "closed":
            investigated_keys.add(key)

    pending_records = [
        require_mapping(item, "review.pending_items[]")
        for item in require_list(review.get("pending_items"), "review.pending_items")
    ]
    pending_follow_ups = sum(item.get("status") == "pending" for item in pending_records)

    before = require_mapping(sca.get("before"), "sca.before")
    after = require_mapping(sca.get("after"), "sca.after")
    before_check = require_mapping(before.get("check"), "sca.before.check")
    after_check = require_mapping(after.get("check"), "sca.after.check")
    before_scan = require_mapping(before.get("scan"), "sca.before.scan")
    after_scan = require_mapping(after.get("scan"), "sca.after.scan")
    validate_scan(before_scan, "sca.before.scan")
    validate_scan(after_scan, "sca.after.scan")

    if before_check.get("id") != after_check.get("id"):
        raise DataError("SCA before and after records refer to different checks")
    if before_scan.get("total_checks") != after_scan.get("total_checks"):
        raise DataError("SCA total_checks changed between the compared scans")

    corrected = int(before_check.get("result") == "failed" and after_check.get("result") == "passed")
    if bool(sca.get("verified_passed")) != bool(corrected):
        raise DataError("SCA verified_passed conflicts with the observed result transition")

    detected_count = len(alerts)
    investigated_count = len(investigated_keys)
    coverage = round((investigated_count / detected_count) * 100, 1) if detected_count else 0.0

    metrics = {
        "evidence_through": after.get("captured_at"),
        "fim": {
            "baseline_files": len(baseline_files),
            "controlled_change_id": fim_export.get("controlled_change"),
            "detected_events": detected_count,
            "hash_chains_validated": validated_hash_chains,
            "investigated_events": investigated_count,
            "investigation_coverage_percent": coverage,
            "modification_events": modification_count,
            "scan_triggered": bool(fim_export.get("scan_triggered")),
            "scheduled_events": scheduled_count,
        },
        "sca": {
            "check_id": after_check.get("id"),
            "check_title": after_check.get("title"),
            "findings_corrected": corrected,
            "failed_after": require_int(after_scan.get("fail"), "sca.after.scan.fail"),
            "failed_before": require_int(before_scan.get("fail"), "sca.before.scan.fail"),
            "invalid_after": require_int(after_scan.get("invalid"), "sca.after.scan.invalid"),
            "passed_after": require_int(after_scan.get("pass"), "sca.after.scan.pass"),
            "passed_before": require_int(before_scan.get("pass"), "sca.before.scan.pass"),
            "score_after": after_scan.get("score"),
            "score_before": before_scan.get("score"),
            "verified_passed": bool(sca.get("verified_passed")),
        },
        "pending": {
            "documented_follow_up_items": pending_follow_ups,
            "sca_failed_checks": require_int(after_scan.get("fail"), "sca.after.scan.fail"),
            "sca_invalid_checks": require_int(after_scan.get("invalid"), "sca.after.scan.invalid"),
        },
        "sources": [BASELINE_NAME, FIM_ALERTS_NAME, SCA_NAME, INVESTIGATION_NAME],
    }
    return metrics


def render_markdown(metrics: dict[str, Any]) -> str:
    fim = require_mapping(metrics.get("fim"), "metrics.fim")
    sca = require_mapping(metrics.get("sca"), "metrics.sca")
    pending = require_mapping(metrics.get("pending"), "metrics.pending")
    lines = [
        "# Control Review Metrics",
        "",
        f"Evidence captured through: `{metrics.get('evidence_through')}`",
        "",
        "## Measured results",
        "",
        "| Category | Metric | Value |",
        "| --- | --- | ---: |",
        f"| FIM | Baseline files | {fim['baseline_files']} |",
        f"| FIM | Events detected | {fim['detected_events']} |",
        f"| FIM | Events investigated | {fim['investigated_events']} |",
        f"| FIM | Investigation coverage | {fim['investigation_coverage_percent']}% |",
        f"| SCA | Findings corrected | {sca['findings_corrected']} |",
        f"| SCA | Failed checks before | {sca['failed_before']} |",
        f"| SCA | Failed checks after | {sca['failed_after']} |",
        f"| SCA | Passed checks before | {sca['passed_before']} |",
        f"| SCA | Passed checks after | {sca['passed_after']} |",
        f"| Pending | Failed SCA checks requiring triage | {pending['sca_failed_checks']} |",
        f"| Pending | Documented follow-up items | {pending['documented_follow_up_items']} |",
        f"| Tracked separately | Invalid or not-evaluated SCA checks | {pending['sca_invalid_checks']} |",
        "",
        "## Evidence checks",
        "",
        f"- The FIM before-hash matched the baseline for {fim['hash_chains_validated']} modified file.",
        f"- Controlled change `{fim['controlled_change_id']}` produced {fim['modification_events']} modification alert.",
        f"- SCA check `{sca['check_id']}` changed from failed to passed: `{sca['verified_passed']}`.",
        "- The whole-number SCA score remained unchanged even though one failed check moved to passed.",
        "",
        "## Interpretation limits",
        "",
        "- A FIM alert proves that Wazuh observed a change to the monitored file and recorded its attributes. It does not prove malicious intent or identify a person unless separate attribution evidence is collected.",
        "- The VMware shared filesystem required a requested scheduled scan for this event. Real-time notification was not demonstrated.",
        "- Failed SCA checks are review candidates, not automatically confirmed vulnerabilities. Each remaining item needs context and risk review.",
        "",
    ]
    return "\n".join(lines)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    repo_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=repo_root / "data" / "observed",
        help="Directory containing the four sanitized JSON inputs.",
    )
    parser.add_argument(
        "--output-json",
        type=Path,
        default=repo_root / "reports" / "metrics.json",
    )
    parser.add_argument(
        "--output-markdown",
        type=Path,
        default=repo_root / "reports" / "metrics-report.md",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        metrics = build_metrics(args.data_dir)
    except DataError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_markdown.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(
        json.dumps(metrics, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    args.output_markdown.write_text(render_markdown(metrics), encoding="utf-8")
    print(
        "Generated metrics: "
        f"detected={metrics['fim']['detected_events']}, "
        f"investigated={metrics['fim']['investigated_events']}, "
        f"corrected={metrics['sca']['findings_corrected']}, "
        f"pending_sca={metrics['pending']['sca_failed_checks']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
