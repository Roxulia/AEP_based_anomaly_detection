import csv
import json
import tempfile
import unittest
from pathlib import Path

from src.aep_anomaly.pipeline import detect_file, load_config, train_model
from src.aep_anomaly.windowing import chronological_split, load_windows


class PipelineWorkflowTests(unittest.TestCase):
    def _write_events(self, path: Path, count: int = 120) -> None:
        fields = ["timestamp", "method", "normalized_uri", "status_class", "raw_line"]
        with path.open("w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=fields)
            writer.writeheader()
            for index in range(count):
                # Mix self and switching transitions so training information scores vary.
                state = ("GET", "/b" if index % 5 in (0, 1) else "/a", "2xx")
                writer.writerow({"timestamp": f"2026-10-01T00:{index // 60:02d}:{index % 60:02d}+00:00",
                                 "method": state[0], "normalized_uri": state[1],
                                 "status_class": state[2], "raw_line": str(index)})

    def test_count_windows_and_chronological_split(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "events.csv"
            self._write_events(path, 20)
            windows = load_windows(path, window_type="fixed_count", size=2)
            self.assertEqual(len(windows), 10)
            self.assertEqual(len(windows[0].states), 2)
            split = chronological_split(windows)
            self.assertEqual((len(split.training), len(split.validation), len(split.testing)), (6, 1, 3))
            self.assertLess(split.training[-1].window_id, split.validation[0].window_id)

    def test_train_save_load_and_score_windows(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            events = root / "events.csv"
            self._write_events(events)
            config = load_config()
            config["window"].update(type="fixed_count", size=2)
            config["split"].update(training=0.65, validation=0.15, testing=0.20)
            config["aep"]["quantile"] = 0.8
            config["density"]["quantile"] = 0.8
            model_dir = root / "model"
            summary = train_model(events, model_dir, config)
            self.assertEqual(summary["training"] + summary["validation"] + summary["testing"], 60)
            output = root / "scores.jsonl"
            self.assertEqual(detect_file(events, model_dir, output), 60)
            result = json.loads(output.read_text(encoding="utf-8").splitlines()[0])
            self.assertIn("least_probable_transitions", result)
            self.assertIn("aep_threshold", result)
            self.assertIn("density_threshold", result)
            self.assertIn("final_anomalous", result)


if __name__ == "__main__":
    unittest.main()
