import csv
import tempfile
import unittest
from pathlib import Path

from src.aep_anomaly.log_parser import LogParser


class LogParserTests(unittest.TestCase):
    def test_writes_separate_sorted_csvs_and_keeps_malformed_lines(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            inputs = root / "logs"
            outputs = root / "processed"
            inputs.mkdir()
            (inputs / "routes-2026-10-02.log").write_text(
                '[2026-10-02 02:00:00] local.INFO: Route request completed. '
                '{"method":"GET","route_name":null,"uri":"/","status":200,"ip":"127.0.0.1"}\n'
                'not a valid log line\n',
                encoding="utf-8",
            )
            (inputs / "controllers-2026-10-02.log").write_text(
                '[2026-10-02 01:00:00] local.INFO: Controller request completed. '
                '{"controller_action":"Closure","status":200}\n',
                encoding="utf-8",
            )
            (inputs / "services-2026-10-02.log").write_text(
                '[2026-10-02 00:00:00] local.INFO: Service operation completed. '
                '{"operation":"ExampleService::handle"}\n'
                '[2026-10-02 00:01:00] local.INFO: Service entry operation completed. '
                '{"operation":"ExampleController@index"}\n',
                encoding="utf-8",
            )

            summary = LogParser().parse_directory(inputs, outputs)

            self.assertEqual(summary["routes"].parsed_rows, 1)
            self.assertEqual(summary["routes"].malformed_rows, 1)
            self.assertEqual(summary["controllers"].parsed_rows, 1)
            self.assertEqual(summary["services"].parsed_rows, 2)
            self.assertEqual(
                {path.name for path in outputs.glob("*.csv")},
                {"routes.csv", "controllers.csv", "services.csv"},
            )

            with (outputs / "routes.csv").open(encoding="utf-8-sig", newline="") as csv_file:
                route_rows = list(csv.DictReader(csv_file))
            self.assertEqual(route_rows[0]["timestamp"], "2026-10-02 02:00:00")
            self.assertEqual(route_rows[0]["method"], "GET")
            self.assertEqual(route_rows[0]["route_name"], "")
            self.assertEqual(route_rows[0]["parse_status"], "ok")
            self.assertEqual(route_rows[1]["parse_status"], "malformed_line")
            self.assertEqual(route_rows[1]["raw_line"], "not a valid log line")

            with (outputs / "services.csv").open(encoding="utf-8-sig", newline="") as csv_file:
                service_rows = list(csv.DictReader(csv_file))
            self.assertEqual(service_rows[0]["operation"], "ExampleService::handle")
            self.assertEqual(service_rows[1]["operation"], "ExampleController@index")


if __name__ == "__main__":
    unittest.main()
