# WireGuard Users Traffic Monitor TUI

[![Test](https://github.com/behnambagheri/mikrotik-wireguard-manager/actions/workflows/test.yml/badge.svg)](https://github.com/behnambagheri/mikrotik-wireguard-manager/actions/workflows/test.yml)
[![Lint](https://github.com/behnambagheri/mikrotik-wireguard-manager/actions/workflows/lint.yml/badge.svg)](https://github.com/behnambagheri/mikrotik-wireguard-manager/actions/workflows/lint.yml)

Use this terminal application to manage your MikroTik RouterOS WireGuard users across multiple routers.

Web mode is available with API + browser UI.

## Features

- Select your router profile at startup (`.env` profiles)
- Use the dashboard (default after router selection) to view:
  - Router details and health
  - CPU / memory / disk usage bars
  - Total bandwidth and per-interface live bandwidth
  - Traffic window stats per interface (off / 1h / 1d / 1w)
  - Alerts panel
  - Top users widgets
  - WG interface health
  - JSON/CSV export
- Manage your client list with:
  - Sort/filter
  - Enable/disable/delete
  - Add client wizard (interface picker, suggested free IP, key generation, client config output)
- Control each client with:
  - Reset usage baseline
  - Set speed limits
  - Set traffic policies (quota + period + over-limit mode)
  - Realtime usage view
- Keep enforcement on the router side:
  - Quota/period/mode enforcement is installed on router schedulers
  - Policies keep working even when TUI is closed

## Requirements

- Python 3.10+
- MikroTik RouterOS v7 with REST endpoint available on target routers
- `wg` command available locally for add-client key generation (WireGuard tools)

## Quick Start

Run:

```bash
python3 wg_tui.py
```

Web:

```bash
pip install -r requirements-web.txt
PYTHONPATH=src python3 -m wg_users_tui.web_cli --host 0.0.0.0 --port 8088
```

Then open `http://127.0.0.1:8088`.

Web highlights:

- Router profile switching without restart
- Dashboard cards (CPU/memory/disk/bandwidth) + interface live table
- Clients table with search, disabled-only filter, clickable sort columns
- Full selected-client details panel and all management actions
- Add client with optional speed/quota/policy inputs
- Diagnostics panel
- Auto refresh control
- Users and dashboard exports (JSON/PDF/CSV)

## Configuration

Create `.env` with one or more router profiles:

```env
Router1={ user=YOUR_USER, password=YOUR_PASSWORD, router_ip=172.16.40.1, endpoint_ip=YOUR_PUBLIC_IP, dns_servers=YOUR_DNS_SERVERS_COMMA_SEPARATED_OR_ROUTER_IP}
Router2={ user=YOUR_USER, password=YOUR_PASSWORD, router_ip=192.168.10.1, endpoint_ip=YOUR_PUBLIC_IP, dns_servers=YOUR_DNS_SERVERS_COMMA_SEPARATED_OR_ROUTER_IP}
```

Profile fields:

- `user` (required)
- `password` (required)
- `router_ip` (required)
- `endpoint_ip` (optional, used in generated client config)
- `dns_servers` (optional, used in generated client config)
- `transport` (optional, `rest`, `api_ssl`, or `api`; default `rest`)
- `use_https` (optional, `true|false`, default `false`)
- `timeout_sec` (optional, default `30`)

Use `transport=api_ssl` or `transport=api` for older RouterOS versions where `/rest` is unavailable (for example some 7.6 builds).

Legacy single-router env is still supported:

- `ROUTER_IP`
- `ROUTER_USER`
- `ROUTER_PASS`

## CLI

To see CLI options:

```bash
python3 wg_tui.py --help
```

Options:

- `--env-file` path to `.env`
- `--state-file` path to local state JSON
- `--version`

## In-App Help

Press `?` on any screen.

## Project Layout

- `wg_tui.py` compatibility launcher
- `src/wg_users_tui/app.py` core TUI + RouterOS logic
- `src/wg_users_tui/cli.py` CLI entry/help
- `src/wg_users_tui/web.py` FastAPI web API + static UI mount
- `src/wg_users_tui/web_api.py` web backend manager (reuses same engine logic)
- `src/wg_users_tui/web_cli.py` web server runner
- `src/wg_users_tui/web_static/index.html` web UI
- `src/wg_users_tui/__main__.py` module entrypoint
- `src/wg_users_tui/__init__.py` package metadata
