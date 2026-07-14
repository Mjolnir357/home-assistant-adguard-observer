# Home Assistant AdGuard DNS Observer

An independently installable Home Assistant app that diagnoses AdGuard Home DNS failures
without retaining a copy of every DNS request.

The observer runs inside Home Assistant OS, discovers the installed AdGuard Home app through
the Supervisor API, reads recent operational logs, and analyzes only a bounded recent query-log
window. It emits an event only when the normalized diagnostic state changes.

## What it distinguishes

- AdGuard API or app unavailable
- Upstream timeout or upstream connection failure
- DNS `SERVFAIL`, `REFUSED`, `FORMERR`, or `NOTIMP`
- Sustained slow-query windows
- AdGuard blocking decisions
- Per-client state changes for explicitly tracked client IPs

This evidence helps separate a query that never reached AdGuard from a query that reached
AdGuard and failed, was blocked, or completed slowly.

## Privacy and persistence

- Full query history is never copied into the observer state.
- Domains are hashed by default with a local random salt.
- Counts alone do not create new events.
- `/data/state.json` is rewritten only when internal diagnostic state changes.
- `/data/events.jsonl` contains only initialization, incident, state-change, and recovery events.
- The event file rotates at the configured size.
- Credentials are read from Home Assistant app options and are never written to events or state.

## Repository layout

```text
repository.yaml
adguard_dns_observer/
  config.yaml
  Dockerfile
  observer.py
  DOCS.md
tests/
```

## Development

```powershell
python -m unittest discover -s tests -v
python -m py_compile adguard_dns_observer\observer.py
docker build -t local/adguard-dns-observer .\adguard_dns_observer
```

See [the app documentation](adguard_dns_observer/DOCS.md) for configuration and deployment.
