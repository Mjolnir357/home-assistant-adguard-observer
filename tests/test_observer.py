from __future__ import annotations

import json
import sys
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
APP_ROOT = PROJECT_ROOT / "adguard_dns_observer"
sys.path.insert(0, str(APP_ROOT))

import observer  # noqa: E402


def query(
    now: datetime,
    *,
    client: str = "192.168.3.238",
    status: str = "NOERROR",
    elapsed: float = 3.5,
    reason: str = "NotFilteredNotFound",
    domain: str = "www.example.com",
    age_seconds: int = 0,
) -> dict[str, object]:
    return {
        "time": (now - timedelta(seconds=age_seconds)).isoformat(),
        "client": client,
        "status": status,
        "elapsedMs": str(elapsed),
        "reason": reason,
        "question": {"name": domain, "type": "A", "class": "IN"},
        "upstream": "https://dns.example/dns-query",
        "cached": False,
    }


class ObserverTests(unittest.TestCase):
    def test_classify_log_line_focuses_on_failures(self) -> None:
        self.assertEqual(
            observer.classify_log_line("upstream failed to exchange: i/o timeout"),
            "upstream_timeout",
        )
        self.assertEqual(observer.classify_log_line("fatal: process crashed"), "process_failure")
        self.assertIsNone(observer.classify_log_line("listening to udp://0.0.0.0:53"))

    def test_domain_hash_is_stable_and_private(self) -> None:
        first = observer.protected_domain("WWW.Example.com.", "hash", "salt")
        second = observer.protected_domain("www.example.com", "hash", "salt")
        self.assertEqual(first, second)
        self.assertTrue(first.startswith("sha256:"))
        self.assertNotIn("example", first)
        self.assertEqual(
            observer.protected_domain("www.example.com", "redact", "salt"), "[redacted]"
        )

    def test_summarize_queries_attributes_client_failures(self) -> None:
        now = datetime(2026, 7, 14, 12, 0, tzinfo=UTC)
        entries = [
            query(now),
            query(now, status="SERVFAIL", elapsed=1400, domain="slow.example.com"),
            query(
                now,
                client="192.168.3.50",
                reason="FilteredBlackList",
                domain="blocked.example.com",
            ),
            query(now, status="SERVFAIL", age_seconds=1200),
        ]
        result = observer.summarize_queries(
            entries,
            now=now,
            window_seconds=600,
            slow_query_ms=1000,
            tracked_clients=("192.168.3.238",),
            domain_privacy="hash",
            domain_salt="test-salt",
        )

        self.assertEqual(result["queries_considered"], 3)
        self.assertEqual(result["dns_errors"], 1)
        self.assertEqual(result["slow_queries"], 1)
        self.assertEqual(result["blocked_queries"], 1)
        self.assertEqual(result["error_statuses"], ["SERVFAIL"])
        self.assertEqual(result["tracked_clients"]["192.168.3.238"]["state"], "error")
        self.assertNotIn("slow.example.com", json.dumps(result))

    def test_signature_ignores_count_only_changes(self) -> None:
        tracked = {
            "192.168.3.238": {
                "state": "error",
                "queries": 1,
                "dns_errors": 1,
                "slow_queries": 0,
                "blocked_queries": 0,
            }
        }
        query_summary = {
            "queries_considered": 1,
            "dns_errors": 1,
            "slow_queries": 0,
            "blocked_queries": 0,
            "error_statuses": ["SERVFAIL"],
            "error_clients": ["192.168.3.238"],
            "slow_clients": [],
            "samples": [],
            "tracked_clients": tracked,
        }
        snapshot = observer.build_snapshot(
            {"supervisor_logs": "ok", "query_log": "ok"}, [], query_summary, 5
        )
        first = observer.snapshot_signature(snapshot)

        snapshot["query_summary"]["queries_considered"] = 25
        snapshot["query_summary"]["dns_errors"] = 12
        snapshot["query_summary"]["tracked_clients"]["192.168.3.238"]["queries"] = 25
        second = observer.snapshot_signature(snapshot)
        self.assertEqual(first, second)

    def test_state_store_writes_only_when_changed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = observer.StateStore(Path(directory) / "state.json")
            state = store.load()
            self.assertFalse(store.save_if_changed(state))
            state["last_event"] = {"event_type": "test"}
            self.assertTrue(store.save_if_changed(state))
            self.assertFalse(store.save_if_changed(state))

    def test_adguard_url_candidates_prefer_dynamic_ingress(self) -> None:
        candidates = observer.adguard_url_candidates(
            "",
            {
                "ip_address": "172.30.32.1",
                "hostname": "a0d7b954_adguard",
                "ingress_port": 63827,
                "ingress_entry": "/api/hassio_ingress/sensitive-token",
            },
        )
        self.assertEqual(
            candidates[0],
            "http://homeassistant:8123/api/hassio_ingress/sensitive-token",
        )
        self.assertIn("http://a0d7b954-adguard:63827", candidates)

    def test_ingress_token_is_redacted_from_reported_endpoint(self) -> None:
        endpoint = observer.redact_url(
            "http://homeassistant:8123/api/hassio_ingress/sensitive-token"
        )
        self.assertEqual(
            endpoint,
            "http://homeassistant:8123/api/hassio_ingress/[redacted]",
        )

    def test_basic_auth_is_not_sent_through_home_assistant_ingress(self) -> None:
        class FakeHttp:
            def __init__(self) -> None:
                self.headers: dict[str, str] = {}

            def get_json(self, _url: str, headers: dict[str, str]) -> dict[str, object]:
                self.headers = headers
                return {"data": []}

        fake_http = FakeHttp()
        client = observer.AdGuardClient(fake_http, "adguard-user", "adguard-password")
        client.query_log(
            ["http://homeassistant:8123/api/hassio_ingress/sensitive-token"],
            50,
        )
        self.assertNotIn("Authorization", fake_http.headers)

    def test_options_reject_empty_collection(self) -> None:
        with self.assertRaisesRegex(observer.ObserverError, "At least one"):
            observer.Options.from_mapping(
                {"collect_supervisor_logs": False, "collect_query_log": False}
            )

    def test_run_cycle_emits_once_when_only_counts_change(self) -> None:
        class FakeObserver:
            def __init__(self) -> None:
                self.count = 0

            def poll(self, now: datetime | None = None) -> dict[str, object]:
                self.count += 1
                query_summary = {
                    "queries_considered": self.count,
                    "dns_errors": self.count,
                    "slow_queries": 0,
                    "blocked_queries": 0,
                    "error_statuses": ["SERVFAIL"],
                    "error_clients": ["192.168.3.238"],
                    "slow_clients": [],
                    "samples": [],
                    "tracked_clients": {
                        "192.168.3.238": {
                            "state": "error",
                            "queries": self.count,
                            "dns_errors": self.count,
                            "slow_queries": 0,
                            "blocked_queries": 0,
                        }
                    },
                }
                snapshot = observer.build_snapshot(
                    {"supervisor_logs": "ok", "query_log": "ok"}, [], query_summary, 5
                )
                snapshot.update(
                    {
                        "observed_at": "2026-07-14T12:00:00+00:00",
                        "adguard_addon_slug": "a0d7b954_adguard",
                        "adguard_endpoint": "http://172.30.32.1:63827",
                    }
                )
                return snapshot

        class FakeSink:
            def __init__(self) -> None:
                self.events: list[dict[str, object]] = []

            def emit(self, event: dict[str, object]) -> None:
                self.events.append(event)

        with tempfile.TemporaryDirectory() as directory:
            store = observer.StateStore(Path(directory) / "state.json")
            state = store.load()
            fake_observer = FakeObserver()
            sink = FakeSink()
            self.assertTrue(observer.run_cycle(fake_observer, store, sink, state))
            first_contents = (Path(directory) / "state.json").read_text(encoding="utf-8")
            self.assertFalse(observer.run_cycle(fake_observer, store, sink, state))
            second_contents = (Path(directory) / "state.json").read_text(encoding="utf-8")
            self.assertEqual(len(sink.events), 1)
            self.assertEqual(first_contents, second_contents)


if __name__ == "__main__":
    unittest.main()
