"""光动力早期试验的运行入口：健康检查与受控流程 HTTP 接口。

所有受控操作通过 POST /api/<资源>/<动作> 调用，请求/响应均为 JSON。
调用方身份由请求头 X-Actor-Id 与 X-Actor-Role 提供，领域模块据此做角色鉴权
与盲态信息隔离。注册中心为进程内单例（TrialRegistry 自身线程安全）。
"""

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from trial import (
    NotFoundError,
    PermissionDeniedError,
    StateConflictError,
    TrialError,
    TrialRegistry,
    ValidationError,
)

SERVICE_ID = "photodynamic-trial"
SERVICE_NAME = "光动力早期试验"

# 进程内单例；测试可替换 service.REGISTRY
REGISTRY = TrialRegistry()

# HTTP 头只能携带 latin-1，角色通过稳定的 ASCII 令牌传入，服务端映射为受控词表
ROLE_TOKENS = {
    "investigator": "研究者",
    "coordinator": "试验协调员",
    "dsmb": "安全委员会",
    "blind_reader": "盲态评价者",
    "monitor": "申办方监查员",
}

# POST 动作路由：(资源, 动作) -> 注册中心方法名
ACTIONS = {
    ("protocols", "create"): "create_protocol",
    ("protocols", "submit"): "submit_protocol_for_approval",
    ("protocols", "approve"): "approve_protocol",
    ("protocols", "retire"): "retire_protocol",
    ("sites", "register"): "register_site",
    ("sites", "review"): "review_site_credentials",
    ("sites", "change_status"): "change_site_status",
    ("subjects", "register"): "register_subject",
    ("subjects", "consent"): "record_consent",
    ("subjects", "withdraw"): "withdraw_consent",
    ("subjects", "screen"): "screen_eligibility",
    ("subjects", "enroll"): "enroll_subject",
    ("lots", "register"): "register_lot",
    ("lots", "change_status"): "change_lot_status",
    ("cohorts", "create"): "create_cohort",
    ("cohorts", "assign"): "assign_cohort",
    ("deviations", "declare"): "declare_emergency_deviation",
    ("deviations", "supplement"): "supplement_deviation",
    ("deviations", "review"): "review_deviation",
    ("saes", "report"): "report_sae",
    ("saes", "review"): "review_sae",
    ("activities", "schedule"): "schedule_activity",
    ("activities", "perform"): "perform_activity",
    ("activities", "delay"): "delay_activity",
    ("artifacts", "register"): "register_artifact",
    ("evaluability", "set"): "set_evaluability",
    ("outcomes", "record"): "record_outcome",
    ("amendments", "submit"): "submit_amendment",
    ("amendments", "review"): "review_amendment",
    ("amendments", "adopt"): "adopt_amendment_at_site",
    ("amendments", "resolve_todo"): "resolve_amendment_todo",
}

# 领域异常类型 -> HTTP 状态（异常自带的 code 作为业务子码原样返回）
ERROR_STATUS = {
    ValidationError: 400,
    PermissionDeniedError: 403,
    NotFoundError: 404,
    StateConflictError: 409,
    TrialError: 400,
}


def health_payload():
    """返回稳定的服务身份信息。"""
    return {"status": "ok", "service": SERVICE_ID, "name": SERVICE_NAME}


class Handler(BaseHTTPRequestHandler):
    """提供健康检查与受控流程 API，供本地联调和运维巡检使用。"""

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            self._write_json(200, health_payload())
            return
        if parsed.path.startswith("/api/"):
            self._handle_api_get(parsed)
            return
        self.send_error(404)

    def do_POST(self):
        parsed = urlparse(self.path)
        if not parsed.path.startswith("/api/"):
            self.send_error(404)
            return
        parts = parsed.path.rstrip("/").split("/")
        # /api/<resource>/<action>
        if len(parts) != 4:
            self._api_not_found()
            return
        resource, action = parts[2], parts[3]
        method_name = ACTIONS.get((resource, action))
        if method_name is None:
            self._api_not_found()
            return
        actor, error = self._actor_from_headers()
        if error:
            self._write_json(error[0], error[1])
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length) if length else b""
            payload = json.loads(raw.decode("utf-8")) if raw else {}
            if not isinstance(payload, dict):
                raise ValidationError("请求体必须是 JSON 对象")
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._write_json(400, {"error": {"code": "validation_error",
                                             "message": "请求体不是合法 JSON"}})
            return
        except TrialError as exc:
            self._write_error(exc)
            return
        try:
            result = getattr(REGISTRY, method_name)(actor, **payload)
        except TrialError as exc:
            self._write_error(exc)
            return
        except TypeError as exc:
            self._write_json(400, {"error": {
                "code": "validation_error",
                "message": f"请求参数不匹配：{exc}"}})
            return
        self._write_json(200, {"data": result})

    def _handle_api_get(self, parsed):
        actor, error = self._actor_from_headers()
        if error:
            self._write_json(error[0], error[1])
            return
        parts = parsed.path.rstrip("/").split("/")
        query = parse_qs(parsed.query)
        try:
            # /api/subjects[/<id>[/timeline|/provenance|/actions|/amendments]],
            # /api/sites/<id>/todos, /api/cohorts, /api/audit,
            # /api/amendments[/<id>[/snapshots]]
            if parts[2] == "subjects" and len(parts) == 3:
                data = REGISTRY.list_subjects(actor)
            elif parts[2] == "subjects" and len(parts) == 4:
                data = REGISTRY.get_subject(actor, parts[3])
            elif len(parts) == 5 and parts[2] == "subjects" and parts[4] == "timeline":
                data = REGISTRY.subject_timeline(actor, parts[3])
            elif len(parts) == 5 and parts[2] == "subjects" and parts[4] == "provenance":
                data = REGISTRY.subject_provenance(actor, parts[3])
            elif len(parts) == 5 and parts[2] == "subjects" and parts[4] == "actions":
                data = REGISTRY.subject_available_actions(actor, parts[3])
            elif len(parts) == 5 and parts[2] == "subjects" and parts[4] == "amendments":
                data = REGISTRY.subject_amendment_todos(
                    actor, parts[3],
                    open_only=query.get("open_only", ["false"])[0].lower()
                    in ("1", "true", "yes"))
            elif len(parts) == 5 and parts[2] == "sites" and parts[4] == "todos":
                kwargs = {}
                if "status" in query:
                    kwargs["status"] = query["status"][0]
                data = REGISTRY.list_site_todos(actor, parts[3], **kwargs)
            elif parts[2] == "cohorts" and len(parts) == 3:
                data = REGISTRY.list_cohorts(actor)
            elif parts[2] == "amendments" and len(parts) == 3:
                data = REGISTRY.list_amendments(actor)
            elif parts[2] == "amendments" and len(parts) == 4:
                data = REGISTRY.get_amendment(actor, parts[3])
            elif len(parts) == 5 and parts[2] == "amendments" and parts[4] == "snapshots":
                data = REGISTRY.amendment_snapshots(actor, parts[3])
            elif parts[2] == "audit" and len(parts) == 3:
                kwargs = {}
                if "target_type" in query:
                    kwargs["target_type"] = query["target_type"][0]
                if "target_id" in query:
                    kwargs["target_id"] = query["target_id"][0]
                data = REGISTRY.audit_trail(**kwargs)
            else:
                self._api_not_found()
                return
        except TrialError as exc:
            self._write_error(exc)
            return
        self._write_json(200, {"data": data})

    def _api_not_found(self):
        self._write_json(404, {"error": {"code": "not_found",
                                         "message": "接口不存在"}})

    def _actor_from_headers(self):
        actor_id = self.headers.get("X-Actor-Id")
        role_token = self.headers.get("X-Actor-Role")
        if not actor_id or not role_token:
            return None, (401, {"error": {
                "code": "authentication_required",
                "message": "缺少 X-Actor-Id 或 X-Actor-Role 请求头"}})
        role = ROLE_TOKENS.get(role_token)
        if role is None:
            return None, (403, {"error": {
                "code": "validation_error",
                "message": f"未知角色令牌：{role_token}；允许：{', '.join(ROLE_TOKENS)}"}})
        return {"id": actor_id, "role": role}, None

    def _write_error(self, exc: TrialError):
        for exc_type in type(exc).__mro__:
            status = ERROR_STATUS.get(exc_type)
            if status is not None:
                break
        else:
            status = 400
        self._write_json(status, {"error": {"code": exc.code, "message": str(exc)}})

    def _write_json(self, status: int, payload: dict):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        return


def main():
    parser = argparse.ArgumentParser(description=SERVICE_NAME)
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.check:
        assert health_payload()["service"] == SERVICE_ID
        assert isinstance(REGISTRY, TrialRegistry)
        print("基础检查通过")
        return
    ThreadingHTTPServer(("0.0.0.0", args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
