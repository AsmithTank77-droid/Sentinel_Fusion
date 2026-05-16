"""
tests/test_watch.py — Tests for Fix 7: sentinel watch file-cursor logic.

Tests _FileCursor directly (no CLI machinery, no sleeping). The watch command's
inner _run_watch_cycle is integration-tested against a temp file.
"""
from __future__ import annotations

import json
import sys
import os
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ["SENTINEL_DB"] = ":memory:"

from interface.commands.watch import _FileCursor, _run_watch_cycle  # noqa: E402


def _write_events(path: Path, events: list[dict]) -> None:
    path.write_text(json.dumps(events))


# ===========================================================================
# _FileCursor
# ===========================================================================

class TestFileCursor:
    def test_no_file_returns_empty(self, tmp_path):
        cursor = _FileCursor(tmp_path / "nonexistent.json")
        assert cursor.poll() == []

    def test_initial_read_returns_all_events(self, tmp_path):
        f = tmp_path / "events.json"
        events = [
            {"timestamp": "2026-05-09T02:00:00Z", "src_ip": "1.1.1.1",
             "dst_ip": "10.0.0.1", "event_type": "port_scan", "severity": "low"},
        ]
        _write_events(f, events)
        cursor = _FileCursor(f)
        result = cursor.poll()
        assert len(result) == 1
        assert result[0]["event_type"] == "port_scan"

    def test_no_change_returns_empty(self, tmp_path):
        f = tmp_path / "events.json"
        _write_events(f, [{"event_type": "port_scan", "src_ip": "1.1.1.1",
                           "dst_ip": "10.0.0.1", "timestamp": "2026-05-09T02:00:00Z",
                           "severity": "low"}])
        cursor = _FileCursor(f)
        cursor.poll()                      # first read
        result = cursor.poll()             # second read, file unchanged
        assert result == []

    def test_new_events_detected_after_append(self, tmp_path):
        f = tmp_path / "events.json"
        ev1 = {"timestamp": "2026-05-09T02:00:00Z", "src_ip": "1.1.1.1",
               "dst_ip": "10.0.0.1", "event_type": "port_scan", "severity": "low"}
        ev2 = {"timestamp": "2026-05-09T02:01:00Z", "src_ip": "1.1.1.1",
               "dst_ip": "10.0.0.1", "event_type": "authentication_failure", "severity": "medium"}
        _write_events(f, [ev1])
        cursor = _FileCursor(f)
        cursor.poll()                      # read ev1

        # Simulate append: write both events with a different mtime
        _write_events(f, [ev1, ev2])
        import os as _os
        _os.utime(f, (f.stat().st_atime, f.stat().st_mtime + 1))

        new = cursor.poll()
        assert len(new) == 1
        assert new[0]["event_type"] == "authentication_failure"

    def test_file_shrink_resets_cursor(self, tmp_path):
        """Log rotation (file shrinks) resets the cursor so new events are processed."""
        f = tmp_path / "events.json"
        ev1 = {"timestamp": "2026-05-09T02:00:00Z", "src_ip": "1.1.1.1",
               "dst_ip": "10.0.0.1", "event_type": "port_scan", "severity": "low"}
        ev2 = {"timestamp": "2026-05-09T02:01:00Z", "src_ip": "2.2.2.2",
               "dst_ip": "10.0.0.2", "event_type": "port_scan", "severity": "low"}
        ev3 = {"timestamp": "2026-05-09T02:02:00Z", "src_ip": "2.2.2.2",
               "dst_ip": "10.0.0.2", "event_type": "authentication_failure", "severity": "medium"}

        _write_events(f, [ev1, ev1, ev1])  # 3 events
        cursor = _FileCursor(f)
        cursor.poll()  # read all 3, count=3
        assert cursor._count == 3

        # Rotation: new file starts with only 1 event (fewer than cursor count)
        import os as _os
        _write_events(f, [ev2])
        _os.utime(f, (f.stat().st_atime, f.stat().st_mtime + 1))

        reset = cursor.poll()
        assert cursor._count == 1  # cursor reset to new length
        assert len(reset) == 1
        assert reset[0]["src_ip"] == "2.2.2.2"

        # Further append after rotation is tracked correctly
        _write_events(f, [ev2, ev3])
        _os.utime(f, (f.stat().st_atime, f.stat().st_mtime + 1))

        more = cursor.poll()
        assert len(more) == 1
        assert more[0]["src_ip"] == "2.2.2.2"
        assert more[0]["event_type"] == "authentication_failure"

    def test_invalid_json_returns_empty(self, tmp_path):
        f = tmp_path / "bad.json"
        f.write_text("not json {{{")
        cursor = _FileCursor(f)
        assert cursor.poll() == []

    def test_non_list_json_returns_empty(self, tmp_path):
        f = tmp_path / "obj.json"
        f.write_text('{"key": "value"}')
        cursor = _FileCursor(f)
        assert cursor.poll() == []

    def test_empty_array_returns_empty(self, tmp_path):
        f = tmp_path / "empty.json"
        _write_events(f, [])
        cursor = _FileCursor(f)
        assert cursor.poll() == []

    def test_count_advances_across_polls(self, tmp_path):
        f = tmp_path / "events.json"
        ev = {"timestamp": "2026-05-09T02:00:00Z", "src_ip": "1.1.1.1",
              "dst_ip": "10.0.0.1", "event_type": "port_scan", "severity": "low"}
        _write_events(f, [ev])
        cursor = _FileCursor(f)
        cursor.poll()
        assert cursor._count == 1


# ===========================================================================
# _run_watch_cycle integration
# ===========================================================================

class TestRunWatchCycle:
    def test_no_new_events_returns_none(self, tmp_path):
        f = tmp_path / "events.json"
        _write_events(f, [])
        cursor = _FileCursor(f)
        cursor.poll()  # drain initial (empty)

        result = _run_watch_cycle({"mock": cursor}, db_path=":memory:", cycle_n=1)
        assert result is None

    def test_new_events_produce_pipeline_result(self, tmp_path):
        f = tmp_path / "events.json"
        events = [
            {"timestamp": "2026-05-09T02:00:00Z", "src_ip": "185.220.101.45",
             "dst_ip": "10.0.0.1", "event_type": "port_scan", "severity": "low"},
            {"timestamp": "2026-05-09T02:01:00Z", "src_ip": "185.220.101.45",
             "dst_ip": "10.0.0.1", "event_type": "authentication_failure", "severity": "medium"},
        ]
        _write_events(f, events)
        cursor = _FileCursor(f)

        result = _run_watch_cycle({"mock": cursor}, db_path=":memory:", cycle_n=1)
        assert result is not None
        assert result["event_count"] == 2
        assert isinstance(result["alerts"], list)

    def test_second_cycle_only_processes_new_events(self, tmp_path):
        f = tmp_path / "events.json"
        ev1 = {"timestamp": "2026-05-09T02:00:00Z", "src_ip": "1.1.1.1",
               "dst_ip": "10.0.0.1", "event_type": "port_scan", "severity": "low"}
        ev2 = {"timestamp": "2026-05-09T02:01:00Z", "src_ip": "1.1.1.1",
               "dst_ip": "10.0.0.1", "event_type": "authentication_failure", "severity": "medium"}

        _write_events(f, [ev1])
        cursor = _FileCursor(f)

        # Cycle 1: ev1
        r1 = _run_watch_cycle({"mock": cursor}, db_path=":memory:", cycle_n=1)
        assert r1 is not None
        assert r1["event_count"] == 1

        # Append ev2 with forced mtime change
        _write_events(f, [ev1, ev2])
        import os as _os
        _os.utime(f, (f.stat().st_atime, f.stat().st_mtime + 1))

        # Cycle 2: only ev2
        r2 = _run_watch_cycle({"mock": cursor}, db_path=":memory:", cycle_n=2)
        assert r2 is not None
        assert r2["event_count"] == 1
        assert r2["normalized_events"][0]["event_type"] == "authentication_failure"
