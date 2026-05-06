#!/usr/bin/env python3
import asyncio
import json
import os
from typing import Any, Dict

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from ..web_api import AddClientRequest, WebManager, load_json_file


class SelectProfileBody(BaseModel):
    name: str


class DefaultProfileBody(BaseModel):
    name: str


class CredentialLoginBody(BaseModel):
    name: str = "default"
    router_ip: str = ""
    user: str = ""
    password: str = ""
    endpoint_ip: str = ""
    dns_servers: str = ""
    transport: str = "rest"
    timeout_sec: str = ""
    use_https: str = ""
    exempt_traffic_dst_list: str = ""
    remember: bool = False


class ProfileCreateBody(BaseModel):
    name: str
    user: str
    password: str
    router_ip: str
    endpoint_ip: str = ""
    dns_servers: str = ""
    transport: str = "rest"
    timeout_sec: str = ""
    use_https: str = ""
    exempt_traffic_dst_list: str = ""


class ProfileUpdateBody(BaseModel):
    new_name: str | None = None
    user: str | None = None
    password: str | None = None
    router_ip: str | None = None
    endpoint_ip: str | None = None
    dns_servers: str | None = None
    transport: str | None = None
    timeout_sec: str | None = None
    use_https: str | None = None
    exempt_traffic_dst_list: str | None = None


class EnableBody(BaseModel):
    enabled: bool


class SpeedBody(BaseModel):
    down_mbps: float = Field(ge=0)
    up_mbps: float = Field(ge=0)


class PolicyBody(BaseModel):
    down_gb: float = Field(default=0, ge=0)
    up_gb: float = Field(default=0, ge=0)
    period: str = "0"
    mode: str = "disable"
    over_down_mbps: float = Field(default=0, ge=0)
    over_up_mbps: float = Field(default=0, ge=0)

class BatchDeleteBody(BaseModel):
    peer_ids: list[str]

class BatchEnableBody(BaseModel):
    peer_ids: list[str]
    enabled: bool

class BatchSpeedBody(BaseModel):
    peer_ids: list[str]
    down_mbps: float = Field(default=0, ge=0)
    up_mbps: float = Field(default=0, ge=0)

class BatchPolicyBody(BaseModel):
    peer_ids: list[str]
    down_gb: float = Field(default=0, ge=0)
    up_gb: float = Field(default=0, ge=0)
    period: str = "0"
    mode: str = "disable"
    over_down_mbps: float = Field(default=0, ge=0)
    over_up_mbps: float = Field(default=0, ge=0)


class GroupBody(BaseModel):
    name: str
    peer_ids: list[str] = []


class GroupUpdateBody(BaseModel):
    name: str | None = None
    peer_ids: list[str] | None = None


class GroupMembersBody(BaseModel):
    peer_ids: list[str]


class GroupSpeedBody(BaseModel):
    down_mbps: float = Field(default=0, ge=0)
    up_mbps: float = Field(default=0, ge=0)


class GroupPolicyBody(BaseModel):
    down_gb: float = Field(default=0, ge=0)
    up_gb: float = Field(default=0, ge=0)
    period: str = "0"
    mode: str = "disable"
    over_down_mbps: float = Field(default=0, ge=0)
    over_up_mbps: float = Field(default=0, ge=0)


class PanelSettingsBody(BaseModel):
    settings: Dict[str, Any] = {}


class AddClientBody(BaseModel):
    interface: str
    ip: str
    comment: str = ""
    speed_down_mbps: float | None = Field(default=None, ge=0)
    speed_up_mbps: float | None = Field(default=None, ge=0)
    limit_down_gb: float | None = Field(default=None, ge=0)
    limit_up_gb: float | None = Field(default=None, ge=0)
    period: str | None = None
    overlimit_mode: str | None = None
    overlimit_down_mbps: float | None = Field(default=None, ge=0)
    overlimit_up_mbps: float | None = Field(default=None, ge=0)


def create_app() -> FastAPI:
    app = FastAPI(title="MikroTik WireGuard Manager Web", version="0.1.0")
    manager = WebManager()

    @app.get("/api/health")
    def health() -> Dict[str, str]:
        return {"status": "ok", "profile": manager.current_profile()}

    @app.get("/api/auth/status")
    def auth_status() -> Dict[str, Any]:
        return manager.auth_status()

    @app.post("/api/auth/login")
    def auth_login(body: CredentialLoginBody) -> Dict[str, str]:
        try:
            return manager.connect_with_credentials(body.model_dump())
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e)) from e

    @app.get("/api/profiles")
    def profiles() -> Dict[str, Any]:
        return {
            "current": manager.current_profile(),
            "default": manager.default_profile(),
            "profiles": manager.list_profiles(),
        }

    @app.get("/api/profiles/{name}")
    def profile_get(name: str) -> Dict[str, Any]:
        try:
            return manager.get_profile(name)
        except Exception as e:
            raise HTTPException(status_code=404, detail=str(e)) from e

    @app.post("/api/profiles")
    def profile_create(body: ProfileCreateBody) -> Dict[str, str]:
        try:
            manager.create_profile(
                body.name,
                {
                    "user": body.user,
                    "password": body.password,
                    "router_ip": body.router_ip,
                    "endpoint_ip": body.endpoint_ip,
                    "dns_servers": body.dns_servers,
                    "transport": body.transport,
                    "timeout_sec": body.timeout_sec,
                    "use_https": body.use_https,
                    "exempt_traffic_dst_list": body.exempt_traffic_dst_list,
                },
            )
            return {"status": "ok", "current": manager.current_profile()}
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e)) from e

    @app.put("/api/profiles/{name}")
    def profile_update(name: str, body: ProfileUpdateBody) -> Dict[str, str]:
        try:
            out = manager.update_profile(name, body.model_dump(exclude_none=True), body.new_name)
            return {"status": "ok", "name": out["name"], "current": manager.current_profile()}
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e)) from e

    @app.delete("/api/profiles/{name}")
    def profile_delete(name: str) -> Dict[str, str]:
        try:
            out = manager.delete_profile(name)
            return {"status": "ok", "current": out["current"]}
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e)) from e

    @app.post("/api/profiles/select")
    def profiles_select(body: SelectProfileBody) -> Dict[str, str]:
        try:
            manager.select_profile(body.name)
            return {"status": "ok", "current": manager.current_profile()}
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e)) from e

    @app.post("/api/profiles/default")
    def profiles_default(body: DefaultProfileBody) -> Dict[str, str]:
        try:
            out = manager.set_default_profile(body.name)
            return {"status": "ok", "default": out["default"]}
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e)) from e

    @app.post("/api/refresh")
    def refresh() -> Dict[str, str]:
        try:
            manager.refresh()
            return {"status": "ok"}
        except Exception as e:
            if "Manager busy during refresh" in str(e):
                return {"status": "busy"}
            raise HTTPException(status_code=500, detail=str(e)) from e

    @app.get("/api/overview")
    def overview() -> Dict[str, Any]:
        try:
            return manager.router_overview()
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e)) from e

    @app.get("/api/interfaces/stats")
    def interface_stats() -> Dict[str, Any]:
        try:
            return {"items": manager.interface_stats()}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e)) from e

    @app.get("/api/interfaces")
    def interfaces() -> Dict[str, Any]:
        try:
            return {"items": manager.list_wireguard_interfaces()}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e)) from e

    @app.get("/api/interfaces/{iface}/suggest-ip")
    def suggest_ip(iface: str) -> Dict[str, str]:
        try:
            return {"ip": manager.suggest_ip(iface)}
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e)) from e

    @app.get("/api/interfaces/{iface}/ip-pool")
    def interface_ip_pool(iface: str) -> Dict[str, Any]:
        try:
            return manager.interface_ip_pool_info(iface)
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e)) from e

    @app.get("/api/clients")
    def clients() -> Dict[str, Any]:
        try:
            return {"items": manager.list_clients()}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e)) from e

    @app.get("/api/clients/{peer_id}")
    def client(peer_id: str) -> Dict[str, Any]:
        try:
            return manager.get_client(peer_id)
        except Exception as e:
            raise HTTPException(status_code=404, detail=str(e)) from e

    @app.get("/api/groups")
    def groups() -> Dict[str, Any]:
        try:
            return {"items": manager.list_groups()}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e)) from e

    @app.post("/api/groups")
    def group_create(body: GroupBody) -> Dict[str, Any]:
        try:
            return manager.create_group(body.name, body.peer_ids)
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e)) from e

    @app.patch("/api/groups/{group_id}")
    def group_update(group_id: str, body: GroupUpdateBody) -> Dict[str, Any]:
        try:
            return manager.update_group(group_id, name=body.name, peer_ids=body.peer_ids)
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e)) from e

    @app.delete("/api/groups/{group_id}")
    def group_delete(group_id: str) -> Dict[str, str]:
        try:
            manager.delete_group(group_id)
            return {"status": "ok"}
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e)) from e

    @app.post("/api/groups/{group_id}/members/add")
    def group_members_add(group_id: str, body: GroupMembersBody) -> Dict[str, Any]:
        try:
            return manager.add_group_members(group_id, body.peer_ids)
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e)) from e

    @app.post("/api/groups/{group_id}/members/remove")
    def group_members_remove(group_id: str, body: GroupMembersBody) -> Dict[str, Any]:
        try:
            return manager.remove_group_members(group_id, body.peer_ids)
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e)) from e

    @app.post("/api/groups/{group_id}/speed")
    def group_speed(group_id: str, body: GroupSpeedBody) -> Dict[str, Any]:
        try:
            return manager.set_group_speed_limits(group_id, body.down_mbps, body.up_mbps)
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e)) from e

    @app.post("/api/groups/{group_id}/policy")
    def group_policy(group_id: str, body: GroupPolicyBody) -> Dict[str, Any]:
        try:
            return manager.set_group_traffic_policy(
                group_id,
                body.down_gb,
                body.up_gb,
                body.period,
                body.mode,
                body.over_down_mbps,
                body.over_up_mbps,
            )
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e)) from e

    @app.post("/api/groups/{group_id}/reset-usage")
    def group_reset_usage(group_id: str) -> Dict[str, Any]:
        try:
            return manager.reset_group_usage(group_id)
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e)) from e

    @app.post("/api/groups/{group_id}/clear-limits")
    def group_clear_limits(group_id: str) -> Dict[str, Any]:
        try:
            return manager.clear_group_limits(group_id)
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e)) from e

    @app.post("/api/clients")
    def client_add(body: AddClientBody) -> Dict[str, str]:
        try:
            req = AddClientRequest(**body.model_dump())
            return manager.add_client(req)
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e)) from e

    @app.delete("/api/clients/{peer_id}")
    def client_delete(peer_id: str) -> Dict[str, str]:
        try:
            manager.delete_client(peer_id)
            return {"status": "ok"}
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e)) from e

    @app.post("/api/batch/clients/delete")
    def batch_clients_delete(body: BatchDeleteBody) -> Dict[str, Any]:
        try:
            return manager.batch_delete_clients(body.peer_ids)
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e)) from e

    @app.post("/api/clients/{peer_id}/enable")
    def client_enable(peer_id: str, body: EnableBody) -> Dict[str, str]:
        try:
            manager.set_enabled(peer_id, body.enabled)
            return {"status": "ok"}
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e)) from e

    @app.post("/api/batch/clients/enable")
    def batch_clients_enable(body: BatchEnableBody) -> Dict[str, Any]:
        try:
            return manager.batch_set_enabled(body.peer_ids, body.enabled)
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e)) from e

    @app.post("/api/clients/{peer_id}/reset-usage")
    def client_reset_usage(peer_id: str) -> Dict[str, str]:
        try:
            manager.reset_usage(peer_id)
            return {"status": "ok"}
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e)) from e

    @app.post("/api/batch/clients/reset-usage")
    def batch_clients_reset_usage(body: BatchDeleteBody) -> Dict[str, Any]:
        try:
            return manager.batch_reset_usage(body.peer_ids)
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e)) from e

    @app.post("/api/clients/{peer_id}/clear-limits")
    def client_clear_limits(peer_id: str) -> Dict[str, str]:
        try:
            manager.clear_limits(peer_id)
            return {"status": "ok"}
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e)) from e

    @app.post("/api/batch/clients/clear-limits")
    def batch_clients_clear_limits(body: BatchDeleteBody) -> Dict[str, Any]:
        try:
            return manager.batch_clear_limits(body.peer_ids)
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e)) from e

    @app.post("/api/clients/{peer_id}/speed")
    def client_speed(peer_id: str, body: SpeedBody) -> Dict[str, str]:
        try:
            manager.set_speed_limits(peer_id, body.down_mbps, body.up_mbps)
            return {"status": "ok"}
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e)) from e

    @app.post("/api/batch/clients/speed")
    def batch_clients_speed(body: BatchSpeedBody) -> Dict[str, Any]:
        try:
            return manager.batch_set_speed_limits(body.peer_ids, body.down_mbps, body.up_mbps)
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e)) from e

    @app.post("/api/clients/{peer_id}/policy")
    def client_policy(peer_id: str, body: PolicyBody) -> Dict[str, str]:
        try:
            manager.set_traffic_policy(
                peer_id,
                body.down_gb,
                body.up_gb,
                body.period,
                body.mode,
                body.over_down_mbps,
                body.over_up_mbps,
            )
            return {"status": "ok"}
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e)) from e

    @app.post("/api/batch/clients/policy")
    def batch_clients_policy(body: BatchPolicyBody) -> Dict[str, Any]:
        try:
            return manager.batch_set_traffic_policy(
                body.peer_ids,
                body.down_gb,
                body.up_gb,
                body.period,
                body.mode,
                body.over_down_mbps,
                body.over_up_mbps,
            )
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e)) from e

    @app.post("/api/clients/{peer_id}/revoke")
    def client_revoke(peer_id: str) -> Dict[str, str]:
        try:
            return manager.revoke_client(peer_id)
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e)) from e

    @app.get("/api/exports/users.json")
    def export_users_json() -> Dict[str, Any]:
        try:
            path = manager.export_users_json()
            data = load_json_file(path)
            return {"file": path, "data": data}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e)) from e

    @app.get("/api/exports/users.pdf")
    def export_users_pdf() -> FileResponse:
        try:
            path = manager.export_users_pdf()
            return FileResponse(path, media_type="application/pdf", filename=os.path.basename(path))
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e)) from e

    @app.get("/api/exports/dashboard.json")
    def export_dashboard_json() -> Dict[str, str]:
        try:
            path = manager.export_dashboard_json()
            return {"file": path}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e)) from e

    @app.get("/api/exports/dashboard.csv")
    def export_dashboard_csv() -> Dict[str, str]:
        try:
            path = manager.export_dashboard_csv()
            return {"file": path}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e)) from e

    @app.get("/api/diagnostics")
    def diagnostics() -> Dict[str, Any]:
        try:
            return {"items": manager.diagnostics()}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e)) from e

    @app.get("/api/panel/settings")
    def panel_settings() -> Dict[str, Any]:
        return {"settings": manager.panel_settings()}

    @app.post("/api/panel/settings")
    def panel_settings_save(body: PanelSettingsBody) -> Dict[str, Any]:
        try:
            return {"settings": manager.save_panel_settings(body.settings)}
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e)) from e

    def build_live_snapshot() -> Dict[str, Any]:
        try:
            refresh_out = manager.refresh()
        except Exception as e:
            if "Manager busy during refresh" not in str(e):
                raise
            refresh_out = {"status": "busy"}
        return {
            "status": refresh_out.get("status", "ok") if isinstance(refresh_out, dict) else "ok",
            "profile": manager.current_profile(),
            "overview": manager.router_overview(),
            "interfaces": manager.interface_stats(),
            "wireguard_interfaces": manager.list_wireguard_interfaces(),
            "groups": manager.list_groups(),
            "clients": manager.list_clients(),
        }

    @app.get("/api/live/events")
    async def live_events(request: Request, interval: float = 5.0) -> StreamingResponse:
        poll_interval = max(1.0, min(float(interval or 5.0), 60.0))

        async def events():
            while not await request.is_disconnected():
                try:
                    snapshot = await asyncio.to_thread(build_live_snapshot)
                    payload = json.dumps(snapshot, ensure_ascii=False)
                    yield f"event: snapshot\ndata: {payload}\n\n"
                except Exception as e:
                    payload = json.dumps({"status": "error", "detail": str(e)}, ensure_ascii=False)
                    yield f"event: live-error\ndata: {payload}\n\n"
                await asyncio.sleep(poll_interval)

        return StreamingResponse(
            events(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )

    static_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "web_static")
    app.mount("/static", StaticFiles(directory=static_dir), name="static-assets")
    app.mount("/", StaticFiles(directory=static_dir, html=True), name="static")
    return app


app = create_app()
