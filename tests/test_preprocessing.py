import csv
import tempfile
import unittest
from pathlib import Path

from src.aep_anomaly import EventEncoder, RouteNormalizer, RoutePreprocessor


class RouteNormalizerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.normalizer = RouteNormalizer()

    def test_normalizes_clear_dynamic_segments_and_strips_query_and_fragment(self) -> None:
        uri = "/users/{platformUser}/550e8400-e29b-41d4-a716-446655440000/123456?expand=1#top"
        self.assertEqual(self.normalizer.normalize(uri), "/users/:id/:id/:id")

    def test_preserves_meaningful_short_numeric_segments_and_route_casing(self) -> None:
        self.assertEqual(self.normalizer.normalize("sonicui/7/Login"), "/sonicui/7/Login")
        self.assertEqual(self.normalizer.normalize("/2018/wp-includes/wlwmanifest.xml"),
                         "/2018/wp-includes/wlwmanifest.xml")

    def test_missing_uri_is_explicitly_unknown(self) -> None:
        self.assertEqual(self.normalizer.normalize(None), "unknown")
        self.assertEqual(self.normalizer.normalize("  "), "unknown")


class EventEncoderTests(unittest.TestCase):
    def test_encodes_method_url_group_and_status_category(self) -> None:
        state = EventEncoder().encode(" get ", "/users/123456?active=true", 404)
        self.assertEqual(state, ("GET", "route.users", "not_found"))

    def test_invalid_fields_are_marked_unknown(self) -> None:
        state = EventEncoder().encode(None, None, "not-a-status")
        self.assertEqual(state, ("unknown", "unknown", "unknown"))


class RoutePreprocessorTests(unittest.TestCase):
    def test_sorts_rows_encodes_states_and_reports_skipped_rows(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            input_csv = root / "routes.csv"
            output_csv = root / "processed" / "route_events.csv"
            rows = [
                {
                    "timestamp": "2026-10-02 02:00:00", "method": "get", "uri": "/users/123456",
                    "status": "200", "parse_status": "ok", "source_file": "routes-b.log",
                    "route_name": "users.show", "raw_line": "later event",
                },
                {
                    "timestamp": "2026-10-02 01:00:00", "method": "POST", "uri": "/users",
                    "status": "201", "parse_status": "ok", "source_file": "routes-a.log",
                    "route_name": "users.store", "raw_line": "earlier event",
                },
                {
                    "timestamp": "2026-10-02 03:00:00", "method": "GET", "uri": "/bad",
                    "status": "500", "parse_status": "invalid_json", "source_file": "routes-a.log",
                    "route_name": "", "raw_line": "malformed raw log",
                },
                {
                    "timestamp": "not-a-time", "method": "GET", "uri": "/bad",
                    "status": "500", "parse_status": "ok", "source_file": "routes-a.log",
                    "route_name": "", "raw_line": "invalid timestamp row",
                },
            ]
            with input_csv.open("w", encoding="utf-8", newline="") as file:
                writer = csv.DictWriter(file, fieldnames=rows[0].keys())
                writer.writeheader()
                writer.writerows(rows)

            summary = RoutePreprocessor().process_csv(input_csv, output_csv)

            self.assertEqual(summary.input_rows, 4)
            self.assertEqual(summary.processed_rows, 2)
            self.assertEqual(summary.skipped_rows, 2)
            self.assertEqual(summary.skipped_by_reason, {"parse_status": 1, "invalid_timestamp": 1})
            with output_csv.open(encoding="utf-8-sig", newline="") as file:
                events = list(csv.DictReader(file))
            self.assertEqual(events[0]["raw_line"], "earlier event")
            self.assertEqual(events[0]["status_class"], "2xx")
            self.assertEqual(events[1]["normalized_uri"], "/users/:id")
            self.assertEqual(events[1]["source_file"], "routes-b.log")


if __name__ == "__main__":
    unittest.main()
