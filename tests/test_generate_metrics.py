import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from generate_metrics import (  # noqa: E402
    BASELINE_NAME,
    FIM_ALERTS_NAME,
    INVESTIGATION_NAME,
    SCA_NAME,
    DataError,
    build_metrics,
    render_markdown,
)


class GenerateMetricsTests(unittest.TestCase):
    def setUp(self):
        self.data_dir = ROOT / "data" / "observed"

    def test_observed_lab_metrics(self):
        metrics = build_metrics(self.data_dir)

        self.assertEqual(metrics["fim"]["baseline_files"], 2)
        self.assertEqual(metrics["fim"]["detected_events"], 1)
        self.assertEqual(metrics["fim"]["investigated_events"], 1)
        self.assertEqual(metrics["sca"]["findings_corrected"], 1)
        self.assertEqual(metrics["pending"]["sca_failed_checks"], 117)
        self.assertEqual(metrics["pending"]["documented_follow_up_items"], 2)
        self.assertIn("Real-time notification was not demonstrated", render_markdown(metrics))

    def test_rejects_mismatched_fim_before_hash(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            for name in (BASELINE_NAME, FIM_ALERTS_NAME, SCA_NAME, INVESTIGATION_NAME):
                source = json.loads((self.data_dir / name).read_text(encoding="utf-8"))
                (temporary / name).write_text(json.dumps(source), encoding="utf-8")

            baseline_path = temporary / BASELINE_NAME
            baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
            changed = copy.deepcopy(baseline)
            changed["files"][0]["sha256"] = "0" * 64
            baseline_path.write_text(json.dumps(changed), encoding="utf-8")

            with self.assertRaises(DataError):
                build_metrics(temporary)


if __name__ == "__main__":
    unittest.main()
