# v1.0.0

MikroTik WireGuard Manager 1.0.0 is the first production-ready web release after the TUI split. It focuses on RouterOS-side enforcement, durable panel preferences, group-aware reporting, and a cleaner deployment path.

## Highlights

- Added RouterOS-enforced group management with shared speed limits, quota policies, reset windows, and member management.
- Added live browser updates through Server-Sent Events so dashboard, client, group, and health data can refresh without a full page reload.
- Added persisted panel preferences in the web state file: theme, visible sections, auto-refresh interval, client filter, sort state, client column order/widths, group collapse state, and Groups panel collapse state.
- Added grouped client table controls: collapse/expand per group, collapse all, expand all, group-first sorting, richer client filters, and in-page fullscreen mode.
- Improved group and client modals with group-aware graphs, blocked individual limits for group members, safer draft preservation during live refresh, and clearer member eligibility.
- Improved user JSON/PDF exports so reports now include groups, members, effective policies, and router metadata.
- Improved dark mode, WG Health layout behavior, dashboard density, and the side panel with a Router Pulse summary.
- Added Dockerfile, Docker Compose, and `./run.sh` for local or Docker startup.
- Added MIT license and refreshed documentation.

## Upgrade Notes

- The web app stores panel preferences in `.wg_web_state.json` or the path configured by `WG_WEB_STATE_FILE`.
- Docker Compose stores state in the `wg-web-data` named volume and reads router profiles from the local `.env` file.
- Active policy enforcement remains on RouterOS. Stopping the web panel does not remove existing RouterOS queues, firewall rules, address lists, or schedulers.
