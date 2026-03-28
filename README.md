# WireGuard Users Traffic Monitor TUI

Production-ready terminal UI for managing MikroTik RouterOS WireGuard users across multiple routers.

## Features

- Multi-router profile selection at startup (`.env` profiles)
- Dashboard (default after router selection):
  - Router details and health
  - CPU / memory / disk usage bars
  - Total bandwidth and per-interface live bandwidth
  - Traffic window stats per interface (off / 1h / 1d / 1w)
  - Alerts panel
  - Top users widgets
  - WG interface health
  - JSON/CSV export
- Client list and management:
  - Sort/filter
  - Enable/disable/delete
  - Add client wizard (interface picker, suggested free IP, key generation, client config output)
- Per-client controls:
  - Reset usage baseline
  - Set speed limits
  - Set traffic policies (quota + period + over-limit mode)
  - Realtime usage view
- Router-side enforcement:
  - Quota/period/mode enforcement is installed on router schedulers
  - Policies keep working even when TUI is closed

## Requirements

- Python 3.10+
- MikroTik RouterOS v7 with REST endpoint available on target routers
- `wg` command available locally for add-client key generation (WireGuard tools)

## Quick Start

```bash
python3 wg_tui.py
```

## Configuration

Use `.env` with one or more router profiles:

```env
Novin_Max={ user=bea, password=YOUR_PASSWORD, router_ip=172.16.40.1, endpoint_ip=77.74.202.60, dns_servers=100.100.100.100,100.100.100.101}
Office_Max={ user=bea, password=YOUR_PASSWORD, router_ip=192.168.10.1, endpoint_ip=178.252.133.58, dns_servers=192.168.10.1}
```

Profile fields:

- `user` (required)
- `password` (required)
- `router_ip` (required)
- `endpoint_ip` (optional, used in generated client config)
- `dns_servers` (optional, used in generated client config)
- `use_https` (optional, `true|false`, default `false`)
- `timeout_sec` (optional, default `30`)

Legacy single-router env is still supported:

- `ROUTER_IP`
- `ROUTER_USER`
- `ROUTER_PASS`

## CLI

```bash
python3 wg_tui.py --help
```

Options:

- `--env-file` path to `.env`
- `--state-file` path to local state JSON
- `--version`

## In-App Help

Press `?` in any screen.

## Project Layout

- `wg_tui.py` compatibility launcher
- `src/wg_users_tui/app.py` core TUI + RouterOS logic
- `src/wg_users_tui/cli.py` CLI entry/help
- `src/wg_users_tui/__main__.py` module entrypoint
- `src/wg_users_tui/__init__.py` package metadata

## Security Notes

- Do not commit real credentials in `.env`
- Restrict MikroTik service access to trusted source IPs
- Prefer HTTPS (`www-ssl`) in production networks
