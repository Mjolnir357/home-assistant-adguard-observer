#!/usr/bin/env python3
"""Change-only AdGuard Home diagnostics for Home Assistant OS."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
import signal
import socket
import ssl
import sys
import time
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit, urlunsplit
from urllib.request import Request, urlopen

DEFAULTS: dict[str, Any] = {
    "poll_interval_seconds": 300,
    "diagnostic_window_seconds": 600,
    "query_log_limit": 500,
    "slow_query_ms": 1000,
    "slow_query_count_threshold": 5,
    "adguard_addon_slug": "",
    "adguard_url": "",
    "adguard_username": "",
    "adguard_password": "",
    "verify_tls": True,
    "collect_supervisor_logs": True,
    "collect_query_log": True,
    "tracked_clients": "",
    "domain_privacy": "hash",
    "event_log_max_bytes": 1_048_576,
    "syslog_enabled": False,
    "syslog_host": "",
    "syslog_port": 5514,
}

DNS_ERROR_STATUSES = {"SERVFAIL", "REFUSED", "FORMERR", "NOTIMP"}
BLOCKED_REASON_PREFIXES = (
    "Filtered",
    "SafeBrowsing",
    "Parental",
    "SafeSearch",
)
LOG_PATTERNS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("resource_failure", ("out of memory", "oom", "killed process")),
    ("process_failure", ("panic", "fatal", "crash", "exited with code")),
    ("upstream_timeout", ("i/o timeout", "upstream timeout", "deadline exceeded")),
    ("connection_refused", ("connection refused",)),
    ("network_unreachable", ("network is unreachable", "no route to host")),
    ("tls_failure", ("tls handshake", "certificate verify failed", "x509:")),
    ("dns_servfail", ("servfail",)),
    ("upstream_failure", ("upstream", "failed to exchange")),
)


class ObserverError(RuntimeError):
    """Expected observer failure with a safe user-facing message."""


class RequestError(ObserverError):
    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


@dataclass(frozen=True)
class Options:
    poll_interval_seconds: int
    diagnostic_window_seconds: int
    query_log_limit: int
    slow_query_ms: int
    slow_query_count_threshold: int
    adguard_addon_slug: str
    adguard_url: str
    adguard_username: str
    adguard_password: str
    verify_tls: bool
    collect_supervisor_logs: bool
    collect_query_log: bool
    tracked_clients: tuple[str, ...]
    domain_privacy: str
    event_log_max_bytes: int
    syslog_enabled: bool
    syslog_host: str
    syslog_port: int

    @classmethod
    def from_mapping(cls, raw: dict[str, Any]) -> Options:
        values = {**DEFAULTS, **raw}
        tracked = values.get("tracked_clients", "")
        if isinstance(tracked, list):
            tracked_clients = tuple(str(item).strip() for item in tracked if str(item).strip())
        else:
            tracked_clients = tuple(
                part.strip() for part in str(tracked).replace(";", ",").split(",") if part.strip()
            )

        result = cls(
            poll_interval_seconds=int(values["poll_interval_seconds"]),
            diagnostic_window_seconds=int(values["diagnostic_window_seconds"]),
            query_log_limit=int(values["query_log_limit"]),
            slow_query_ms=int(values["slow_query_ms"]),
            slow_query_count_threshold=int(values["slow_query_count_threshold"]),
            adguard_addon_slug=str(values["adguard_addon_slug"]).strip(),
            adguard_url=str(values["adguard_url"]).strip().rstrip("/"),
            adguard_username=str(values["adguard_username"]),
            adguard_password=str(values["adguard_password"]),
            verify_tls=bool(values["verify_tls"]),
            collect_supervisor_logs=bool(values["collect_supervisor_logs"]),
            collect_query_log=bool(values["collect_query_log"]),
            tracked_clients=tracked_clients,
            domain_privacy=str(values["domain_privacy"]).lower(),
            event_log_max_bytes=int(values["event_log_max_bytes"]),
            syslog_enabled=bool(values["syslog_enabled"]),
            syslog_host=str(values["syslog_host"]).strip(),
            syslog_port=int(values["syslog_port"]),
        )
        result.validate()
        return result

    def validate(self) -> None:
        if not self.collect_supervisor_logs and not self.collect_query_log:
            raise ObserverError("At least one collection method must be enabled")
        if self.domain_privacy not in {"hash", "redact", "plain"}:
            raise ObserverError("domain_privacy must be hash, redact, or plain")
        if self.poll_interval_seconds < 60:
            raise ObserverError("poll_interval_seconds must be at least 60")
        if self.diagnostic_window_seconds < 60:
            raise ObserverError("diagnostic_window_seconds must be at least 60")
        if self.syslog_enabled and not self.syslog_host:
            raise ObserverError("syslog_host is required when syslog is enabled")


class StateStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._serialized = ""

    def load(self) -> dict[str, Any]:
        if self.path.exists():
            try:
                state = json.loads(self.path.read_text(encoding="utf-8-sig"))
            except (OSError, json.JSONDecodeError) as exc:
                raise ObserverError(f"Cannot read state file: {exc}") from exc
        else:
            state = {}

        state.setdefault("version", 1)
        state.setdefault("domain_salt", secrets.token_hex(16))
        state.setdefault("log_baseline_complete", False)
        state.setdefault("seen_log_hashes", [])
        state.setdefault("last_signature", None)
        state.setdefault("last_event", None)
        self._serialized = canonical_json(state)
        return state

    def save_if_changed(self, state: dict[str, Any]) -> bool:
        serialized = canonical_json(state)
        if serialized == self._serialized:
            return False
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        temporary.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(temporary, self.path)
        self._serialized = serialized
        return True


class HttpClient:
    def __init__(self, verify_tls: bool, timeout_seconds: int = 12) -> None:
        self.timeout_seconds = timeout_seconds
        self.ssl_context = ssl.create_default_context()
        if not verify_tls:
            self.ssl_context.check_hostname = False
            self.ssl_context.verify_mode = ssl.CERT_NONE

    def get(self, url: str, headers: dict[str, str] | None = None) -> tuple[bytes, str]:
        request = Request(url, method="GET", headers=headers or {})
        try:
            with urlopen(
                request,
                timeout=self.timeout_seconds,
                context=self.ssl_context if url.startswith("https:") else None,
            ) as response:
                return response.read(), response.headers.get("Content-Type", "")
        except HTTPError as exc:
            message = "authentication_required" if exc.code in {401, 403} else f"http_{exc.code}"
            raise RequestError(message, status=exc.code) from exc
        except (URLError, TimeoutError, OSError) as exc:
            reason = getattr(exc, "reason", None)
            label = type(reason or exc).__name__.lower()
            raise RequestError(f"connection_{label}") from exc

    def get_json(self, url: str, headers: dict[str, str] | None = None) -> dict[str, Any]:
        body, _ = self.get(url, headers)
        try:
            result = json.loads(body.decode("utf-8-sig"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RequestError("invalid_json_response") from exc
        if not isinstance(result, dict):
            raise RequestError("unexpected_json_response")
        return result


class SupervisorClient:
    def __init__(self, http: HttpClient, token: str, base_url: str = "http://supervisor") -> None:
        if not token:
            raise ObserverError("SUPERVISOR_TOKEN is unavailable")
        self.http = http
        self.base_url = base_url.rstrip("/")
        self.headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}

    def _json(self, path: str) -> dict[str, Any]:
        payload = self.http.get_json(f"{self.base_url}{path}", self.headers)
        data = payload.get("data", payload)
        if not isinstance(data, dict):
            raise RequestError("unexpected_supervisor_response")
        return data

    def discover_adguard(self, configured_slug: str = "") -> tuple[str, dict[str, Any]]:
        if configured_slug:
            slug = configured_slug
        else:
            addons = self._json("/addons").get("addons", [])
            candidates = [
                addon
                for addon in addons
                if isinstance(addon, dict)
                and (
                    "adguard" in str(addon.get("slug", "")).lower()
                    or "adguard" in str(addon.get("name", "")).lower()
                )
                and addon.get("state") != "stopped"
            ]
            if not candidates:
                raise ObserverError("No running AdGuard Home app was found")
            slug = str(candidates[0]["slug"])

        info = self._json(f"/addons/{quote(slug, safe='')}/info")
        if info.get("state") == "stopped":
            raise ObserverError("The configured AdGuard Home app is stopped")
        return slug, info

    def addon_logs(self, slug: str, lines: int = 500) -> str:
        query = urlencode({"lines": lines, "no_colors": ""})
        headers = {**self.headers, "Accept": "text/plain"}
        body, _ = self.http.get(
            f"{self.base_url}/addons/{quote(slug, safe='')}/logs?{query}", headers
        )
        return body.decode("utf-8", errors="replace")


class AdGuardClient:
    def __init__(self, http: HttpClient, username: str = "", password: str = "") -> None:
        self.http = http
        self.headers = {"Accept": "application/json"}
        if username or password:
            token = base64.b64encode(f"{username}:{password}".encode()).decode()
            self.headers["Authorization"] = f"Basic {token}"

    def query_log(self, base_urls: list[str], limit: int) -> tuple[list[dict[str, Any]], str]:
        failures: list[str] = []
        for base_url in base_urls:
            url = f"{base_url.rstrip('/')}/control/querylog?{urlencode({'limit': limit})}"
            try:
                payload = self.http.get_json(url, self.headers)
                entries = payload.get("data", [])
                if not isinstance(entries, list):
                    raise RequestError("unexpected_query_log_response")
                return [item for item in entries if isinstance(item, dict)], redact_url(base_url)
            except RequestError as exc:
                failures.append(str(exc))

        if "authentication_required" in failures:
            raise RequestError("authentication_required")
        if failures:
            raise RequestError(failures[-1])
        raise RequestError("no_adguard_endpoint_candidates")


class EventSink:
    def __init__(
        self, path: Path, max_bytes: int, syslog_host: str = "", syslog_port: int = 5514
    ) -> None:
        self.path = path
        self.max_bytes = max_bytes
        self.syslog_host = syslog_host
        self.syslog_port = syslog_port

    def emit(self, event: dict[str, Any]) -> None:
        serialized = json.dumps(event, sort_keys=True, separators=(",", ":"))
        print(f"ADGUARD_DNS_OBSERVER {serialized}", flush=True)
        self._append(serialized)
        if self.syslog_host:
            self._send_syslog(serialized)

    def _append(self, serialized: str) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        encoded = (serialized + "\n").encode("utf-8")
        try:
            current_size = self.path.stat().st_size
        except FileNotFoundError:
            current_size = 0
        if current_size + len(encoded) > self.max_bytes:
            rotated = self.path.with_suffix(self.path.suffix + ".1")
            if rotated.exists():
                rotated.unlink()
            if self.path.exists():
                os.replace(self.path, rotated)
        with self.path.open("ab") as handle:
            handle.write(encoded)

    def _send_syslog(self, serialized: str) -> None:
        message = f"<134>ADGUARD_DNS_OBSERVER {serialized}".encode()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(2)
                sock.sendto(message, (self.syslog_host, self.syslog_port))
        except OSError as exc:
            print(f"[warning] syslog delivery failed: {type(exc).__name__}", file=sys.stderr)


class Observer:
    def __init__(
        self,
        options: Options,
        state: dict[str, Any],
        supervisor: SupervisorClient,
        adguard: AdGuardClient,
    ) -> None:
        self.options = options
        self.state = state
        self.supervisor = supervisor
        self.adguard = adguard

    def poll(self, now: datetime | None = None) -> dict[str, Any]:
        now = now or datetime.now(UTC)
        access = {"supervisor_logs": "disabled", "query_log": "disabled"}
        operational_categories: list[str] = []
        query_summary = empty_query_summary(self.options.tracked_clients)
        endpoint = None

        slug = ""
        info: dict[str, Any] = {}
        discovery_error: str | None = None
        try:
            slug, info = self.supervisor.discover_adguard(self.options.adguard_addon_slug)
        except ObserverError as exc:
            discovery_error = safe_error(exc)

        if self.options.collect_supervisor_logs:
            if discovery_error:
                access["supervisor_logs"] = f"error:{discovery_error}"
            else:
                try:
                    log_text = self.supervisor.addon_logs(slug)
                    operational_categories = self._new_log_categories(log_text)
                    access["supervisor_logs"] = "ok"
                except ObserverError as exc:
                    access["supervisor_logs"] = f"error:{safe_error(exc)}"

        if self.options.collect_query_log:
            if discovery_error and not self.options.adguard_url:
                access["query_log"] = f"error:{discovery_error}"
            else:
                try:
                    urls = adguard_url_candidates(self.options.adguard_url, info)
                    entries, endpoint = self.adguard.query_log(urls, self.options.query_log_limit)
                    query_summary = summarize_queries(
                        entries=entries,
                        now=now,
                        window_seconds=self.options.diagnostic_window_seconds,
                        slow_query_ms=self.options.slow_query_ms,
                        tracked_clients=self.options.tracked_clients,
                        domain_privacy=self.options.domain_privacy,
                        domain_salt=str(self.state["domain_salt"]),
                    )
                    access["query_log"] = "ok"
                except ObserverError as exc:
                    access["query_log"] = f"error:{safe_error(exc)}"

        snapshot = build_snapshot(
            access=access,
            operational_categories=operational_categories,
            query_summary=query_summary,
            slow_query_count_threshold=self.options.slow_query_count_threshold,
        )
        snapshot["observed_at"] = now.isoformat()
        snapshot["adguard_addon_slug"] = slug or None
        snapshot["adguard_endpoint"] = endpoint
        return snapshot

    def _new_log_categories(self, log_text: str) -> list[str]:
        classified: list[tuple[str, str]] = []
        for line in log_text.splitlines():
            category = classify_log_line(line)
            if category:
                digest = hashlib.sha256(line.strip().encode("utf-8", errors="replace")).hexdigest()
                classified.append((digest, category))

        seen = list(self.state.get("seen_log_hashes", []))
        seen_set = set(seen)
        current_hashes = [digest for digest, _ in classified]
        if not self.state.get("log_baseline_complete", False):
            self.state["log_baseline_complete"] = True
            self.state["seen_log_hashes"] = current_hashes[-512:]
            return []

        new_items = [
            (digest, category) for digest, category in classified if digest not in seen_set
        ]
        if new_items:
            seen.extend(digest for digest, _ in new_items)
            self.state["seen_log_hashes"] = seen[-512:]
        return sorted({category for _, category in new_items})


def load_options(path: Path) -> Options:
    try:
        raw = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ObserverError(f"Cannot read options: {exc}") from exc
    if not isinstance(raw, dict):
        raise ObserverError("Options must be a JSON object")
    return Options.from_mapping(raw)


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def safe_error(error: BaseException) -> str:
    message = str(error).strip().lower().replace(" ", "_")
    allowed = "abcdefghijklmnopqrstuvwxyz0123456789_:-"
    cleaned = "".join(character for character in message if character in allowed)
    return cleaned[:120] or type(error).__name__.lower()


def redact_url(url: str) -> str:
    parts = urlsplit(url)
    hostname = parts.hostname or "unknown"
    netloc = hostname
    if parts.port:
        netloc = f"{hostname}:{parts.port}"
    return urlunsplit((parts.scheme, netloc, parts.path.rstrip("/"), "", ""))


def adguard_url_candidates(override: str, info: dict[str, Any]) -> list[str]:
    if override:
        return [override.rstrip("/")]

    candidates: list[str] = []
    ip_address = str(info.get("ip_address") or "").strip()
    hostname = str(info.get("hostname") or "").strip().replace("_", "-")
    ingress_port = int(info.get("ingress_port") or 0)

    if ip_address and ingress_port:
        candidates.append(f"http://{ip_address}:{ingress_port}")
    if hostname and ingress_port:
        candidates.append(f"http://{hostname}:{ingress_port}")
    if ip_address:
        candidates.append(f"http://{ip_address}:80")
    if hostname:
        candidates.append(f"http://{hostname}:80")
    return list(dict.fromkeys(candidates))


def classify_log_line(line: str) -> str | None:
    lowered = line.lower()
    for category, patterns in LOG_PATTERNS:
        if category == "upstream_failure":
            if all(pattern in lowered for pattern in patterns):
                return category
        elif any(pattern in lowered for pattern in patterns):
            return category
    return None


def parse_time(value: Any) -> datetime | None:
    if not value:
        return None
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def elapsed_ms(entry: dict[str, Any]) -> float:
    try:
        return float(entry.get("elapsedMs", 0) or 0)
    except (TypeError, ValueError):
        return 0.0


def protected_domain(domain: str, mode: str, salt: str) -> str:
    normalized = domain.strip().lower().rstrip(".")
    if not normalized:
        return "unknown"
    if mode == "plain":
        return normalized
    if mode == "redact":
        return "[redacted]"
    digest = hashlib.sha256(f"{salt}:{normalized}".encode()).hexdigest()[:16]
    return f"sha256:{digest}"


def is_blocked_reason(reason: str) -> bool:
    return reason.startswith(BLOCKED_REASON_PREFIXES)


def empty_query_summary(tracked_clients: tuple[str, ...]) -> dict[str, Any]:
    return {
        "queries_considered": 0,
        "dns_errors": 0,
        "slow_queries": 0,
        "blocked_queries": 0,
        "error_statuses": [],
        "error_clients": [],
        "slow_clients": [],
        "samples": [],
        "tracked_clients": {
            client: {
                "state": "inactive",
                "queries": 0,
                "dns_errors": 0,
                "slow_queries": 0,
                "blocked_queries": 0,
            }
            for client in tracked_clients
        },
    }


def summarize_queries(
    entries: list[dict[str, Any]],
    now: datetime,
    window_seconds: int,
    slow_query_ms: int,
    tracked_clients: tuple[str, ...],
    domain_privacy: str,
    domain_salt: str,
) -> dict[str, Any]:
    cutoff = now - timedelta(seconds=window_seconds)
    summary = empty_query_summary(tracked_clients)
    error_statuses: Counter[str] = Counter()
    error_clients: Counter[str] = Counter()
    slow_clients: Counter[str] = Counter()
    samples: list[dict[str, Any]] = []

    precedence = {"inactive": 0, "successful": 1, "blocked": 2, "slow": 3, "error": 4}

    for entry in entries:
        timestamp = parse_time(entry.get("time"))
        if timestamp is None or timestamp < cutoff or timestamp > now + timedelta(minutes=5):
            continue

        client = str(entry.get("client") or "unknown")
        status = str(entry.get("status") or "UNKNOWN").upper()
        reason = str(entry.get("reason") or "")
        duration = elapsed_ms(entry)
        blocked = is_blocked_reason(reason)
        dns_error = status in DNS_ERROR_STATUSES
        slow = duration >= slow_query_ms
        question = entry.get("question") if isinstance(entry.get("question"), dict) else {}
        domain = protected_domain(str(question.get("name") or ""), domain_privacy, domain_salt)

        summary["queries_considered"] += 1
        if dns_error:
            summary["dns_errors"] += 1
            error_statuses[status] += 1
            error_clients[client] += 1
        if slow:
            summary["slow_queries"] += 1
            slow_clients[client] += 1
        if blocked:
            summary["blocked_queries"] += 1

        if (dns_error or slow) and len(samples) < 10:
            samples.append(
                {
                    "client": client,
                    "status": status,
                    "elapsed_ms": round(duration, 3),
                    "cached": bool(entry.get("cached", False)),
                    "upstream": str(entry.get("upstream") or "unknown")[:200],
                    "domain": domain,
                    "observed_at": timestamp.isoformat(),
                }
            )

        if client in summary["tracked_clients"]:
            tracked = summary["tracked_clients"][client]
            tracked["queries"] += 1
            tracked["dns_errors"] += int(dns_error)
            tracked["slow_queries"] += int(slow)
            tracked["blocked_queries"] += int(blocked)
            candidate_state = (
                "error" if dns_error else "slow" if slow else "blocked" if blocked else "successful"
            )
            if precedence[candidate_state] > precedence[tracked["state"]]:
                tracked["state"] = candidate_state

    summary["error_statuses"] = sorted(error_statuses)
    summary["error_clients"] = sorted(error_clients)
    summary["slow_clients"] = sorted(slow_clients)
    summary["samples"] = samples
    return summary


def build_snapshot(
    access: dict[str, str],
    operational_categories: list[str],
    query_summary: dict[str, Any],
    slow_query_count_threshold: int,
) -> dict[str, Any]:
    access_errors = sorted(key for key, value in access.items() if value.startswith("error:"))
    slow_incident = query_summary["slow_queries"] >= slow_query_count_threshold
    health = (
        "degraded"
        if access_errors
        or operational_categories
        or query_summary["dns_errors"] > 0
        or slow_incident
        else "healthy"
    )
    severity = "error" if access_errors else "warning" if health == "degraded" else "info"
    return {
        "health": health,
        "severity": severity,
        "access": access,
        "operational_categories": sorted(set(operational_categories)),
        "query_summary": query_summary,
        "slow_query_incident": slow_incident,
    }


def snapshot_signature(snapshot: dict[str, Any]) -> dict[str, Any]:
    query = snapshot["query_summary"]
    return {
        "health": snapshot["health"],
        "access": snapshot["access"],
        "operational_categories": snapshot["operational_categories"],
        "error_statuses": query["error_statuses"],
        "error_clients": query["error_clients"],
        "slow_incident_clients": query["slow_clients"] if snapshot["slow_query_incident"] else [],
        "tracked_client_states": {
            client: details["state"] for client, details in query["tracked_clients"].items()
        },
    }


def transition_event(previous: dict[str, Any] | None, snapshot: dict[str, Any]) -> dict[str, Any]:
    current_signature = snapshot_signature(snapshot)
    if previous is None:
        event_type = "observer_initialized"
    elif previous.get("health") != "healthy" and snapshot["health"] == "healthy":
        event_type = "recovery"
    else:
        event_type = "diagnostic_state_change"
    return {
        "integration": "adguard_dns_observer",
        "event_type": event_type,
        "severity": snapshot["severity"],
        "observed_at": snapshot["observed_at"],
        "signature": current_signature,
        "details": {
            "adguard_addon_slug": snapshot["adguard_addon_slug"],
            "adguard_endpoint": snapshot["adguard_endpoint"],
            "query_summary": snapshot["query_summary"],
        },
    }


def run_cycle(
    observer: Observer,
    store: StateStore,
    sink: EventSink,
    state: dict[str, Any],
    now: datetime | None = None,
) -> bool:
    snapshot = observer.poll(now=now)
    signature = snapshot_signature(snapshot)
    previous = state.get("last_signature")
    emitted = canonical_json(previous) != canonical_json(signature)
    if emitted:
        event = transition_event(previous, snapshot)
        sink.emit(event)
        state["last_signature"] = signature
        state["last_event"] = {
            "event_type": event["event_type"],
            "observed_at": event["observed_at"],
        }
    store.save_if_changed(state)
    return emitted


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=Path("/data/options.json"))
    parser.add_argument("--state", type=Path, default=Path("/data/state.json"))
    parser.add_argument("--events", type=Path, default=Path("/data/events.jsonl"))
    parser.add_argument("--once", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        options = load_options(args.config)
        store = StateStore(args.state)
        state = store.load()
        http = HttpClient(verify_tls=options.verify_tls)
        supervisor = SupervisorClient(http, os.environ.get("SUPERVISOR_TOKEN", ""))
        adguard = AdGuardClient(http, options.adguard_username, options.adguard_password)
        observer = Observer(options, state, supervisor, adguard)
        sink = EventSink(
            args.events,
            options.event_log_max_bytes,
            options.syslog_host if options.syslog_enabled else "",
            options.syslog_port,
        )
    except ObserverError as exc:
        print(f"[fatal] {exc}", file=sys.stderr)
        return 2

    stopping = False

    def stop(_signum: int, _frame: Any) -> None:
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    print(
        "AdGuard DNS Observer started; only initialization and diagnostic "
        "state changes are emitted",
        flush=True,
    )

    while not stopping:
        try:
            run_cycle(observer, store, sink, state)
        except Exception as exc:  # noqa: BLE001 - daemon must survive a failed poll
            print(f"[error] poll failed safely: {safe_error(exc)}", file=sys.stderr, flush=True)
        if args.once:
            break
        deadline = time.monotonic() + options.poll_interval_seconds
        while not stopping and time.monotonic() < deadline:
            time.sleep(min(1.0, max(0.0, deadline - time.monotonic())))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
