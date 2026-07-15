# Changelog

## 0.1.3

- Obtain a short-lived Home Assistant ingress session before reading the AdGuard query log.
- Authenticate through Home Assistant Core with the rotating app token instead of storing user credentials.
- Keep ingress cookies and tokens out of diagnostic event output.

## 0.1.2

- Grant the Supervisor `manager` role required to discover and inspect the separate AdGuard app.
- Document the elevated permission boundary and the observer's read-only Supervisor behavior.
- Add CI enforcement requiring app changes to increase the Home Assistant app version.

## 0.1.1

- Route automatic AdGuard API access through Home Assistant's authenticated ingress proxy.
- Stop misclassifying the AdGuard ingress IP allowlist response as bad credentials.
- Redact the private ingress token from diagnostic event output.
- Never forward configured AdGuard Basic credentials through Home Assistant ingress.

## 0.1.0

- Initial standalone Home Assistant app repository.
- Supervisor-based AdGuard discovery and operational-log collection.
- Failure-focused query-log analysis with domain privacy controls.
- Change-only state and event persistence.
- Optional Wazuh/syslog transition output.
