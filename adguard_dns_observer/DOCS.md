# AdGuard DNS Observer

## Purpose

This app collects enough AdGuard evidence to determine whether DNS failures are occurring inside
AdGuard, at its upstream resolvers, or before the request reaches AdGuard. It deliberately avoids
building a second permanent DNS query history.

## How it connects

The app requests the minimum Home Assistant Supervisor access needed to:

1. Find the running AdGuard Home app.
2. Read the AdGuard app's recent operational logs.
3. Discover AdGuard's private Home Assistant ingress entry.
4. Query `/control/querylog` through Home Assistant's internal ingress proxy.

It does not require SSH, host networking, Docker access, privileged mode, or a new LAN port.

### Supervisor permission boundary

Home Assistant requires the Supervisor `manager` role before one app can discover or read the
details and logs of another installed app. AdGuard DNS Observer therefore declares
`hassio_role: manager`. The observer itself issues only Supervisor `GET` requests; it contains no
code path that starts, stops, updates, reconfigures, or removes an app. This permission is broader
than the operations the observer performs, but a lower Supervisor role returns `403` for the
required AdGuard discovery and log endpoints.

## Initial configuration

The defaults track `192.168.3.238`, the current address associated with the unidentified client.
Multiple tracked addresses can be entered as a comma-separated string.

Leave `adguard_addon_slug` and `adguard_url` empty for automatic discovery. Automatic discovery
uses Home Assistant ingress and does not require an AdGuard username or password. The optional
AdGuard credentials are used only when `adguard_url` explicitly points to a direct AdGuard API
that requires HTTP Basic authentication.

Recommended initial values:

```yaml
poll_interval_seconds: 300
diagnostic_window_seconds: 600
slow_query_ms: 1000
slow_query_count_threshold: 5
tracked_clients: "192.168.3.238"
domain_privacy: hash
```

## Events

The app writes one JSON line for each normalized state transition to `/data/events.jsonl` and
prints the same structured event to the Home Assistant app log. Counts changing within the same
incident do not produce more events.

Possible event types:

- `observer_initialized`
- `diagnostic_state_change`
- `recovery`

Tracked-client states are:

- `inactive`: no query from the client occurred in the current diagnostic window
- `successful`: recent queries completed without an error, slow result, or block
- `blocked`: AdGuard deliberately filtered the query
- `slow`: the query exceeded `slow_query_ms`
- `error`: AdGuard returned a diagnostic DNS error status

## Wazuh integration

Set `syslog_enabled` to `true`, then configure the Wazuh manager address and UDP listener port.
Only transition events are sent. The message begins with `ADGUARD_DNS_OBSERVER` followed by JSON,
so a dedicated Wazuh decoder and rule can be added later without changing this app.

## Domain privacy

- `hash` is the recommended default. It emits a stable, locally salted identifier.
- `redact` emits `[redacted]` for every domain.
- `plain` retains the queried domain in incident samples and should be used only temporarily.

## First-run behavior

Existing operational failure lines are baselined so old log history does not immediately alert.
Current query-log entries are considered only if their timestamps fall inside the diagnostic
window. The first event records the initial diagnostic state; further events occur only on change.

## Installation status

Until this repository is published, it can be tested as a local Home Assistant app by copying the
`adguard_dns_observer` folder into `/addons/adguard_dns_observer`, reloading the app store, building,
and starting the local app. Once published, add the repository URL through the Home Assistant app
store and install it normally.
