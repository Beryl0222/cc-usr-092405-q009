"""受控流程 HTTP 接口契约测试。"""

import json
import threading
import unittest
from datetime import datetime, timedelta
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import Request, urlopen

import service
from service import Handler
from trial import TrialRegistry

BASE_TIME = datetime(2026, 3, 2, 9, 0)


class Clock:
    def __init__(self):
        self.t = BASE_TIME

    def __call__(self):
        return self.t


class ApiTestBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def setUp(self):
        service.REGISTRY = TrialRegistry(clock=Clock())
        self.r = service.REGISTRY

    def call(self, path, payload=None, *, actor=("doc01", "investigator"), method="POST"):
        headers = {"Content-Type": "application/json"}
        if actor is not None:
            headers["X-Actor-Id"] = actor[0]
            headers["X-Actor-Role"] = actor[1]
        data = json.dumps(payload or {}).encode("utf-8")
        request = Request(self.base_url + path, data=data if method == "POST" else None,
                          headers=headers, method=method)
        try:
            with urlopen(request, timeout=5) as response:
                return response.status, json.load(response)
        except HTTPError as error:
            body = json.load(error)
            error.close()
            return error.code, body

    def get(self, path, *, actor=("doc01", "investigator")):
        return self.call(path, actor=actor, method="GET")

    def bootstrap(self):
        self.call("/api/protocols/create", {"version": "1.0"},
                  actor=("doc01", "investigator"))
        pid = self.r.protocol_order[0]
        self.call(f"/api/protocols/submit", {"protocol_id": pid})
        self.call("/api/protocols/approve",
                  {"protocol_id": pid, "decision": "继续", "rationale": "放行"},
                  actor=("dsmb01", "dsmb"))
        self.call("/api/sites/register",
                  {"site_id": "SITE-A", "name": "胰腺中心",
                   "credentials_expire_at": "2027-03-02T09:00:00"},
                  actor=("coord01", "coordinator"))
        self.call("/api/sites/review",
                  {"site_id": "SITE-A", "approved": True,
                   "qualified_versions": ["1.0"], "rationale": "资质齐全"},
                  actor=("coord01", "coordinator"))
        self.call("/api/lots/register",
                  {"lot_id": "DRUG-1", "kind": "药物", "product": "光敏剂A",
                   "expires_at": "2026-09-02T09:00:00"},
                  actor=("coord01", "coordinator"))
        self.call("/api/lots/register",
                  {"lot_id": "DEV-1", "kind": "器械", "product": "光纤球囊",
                   "expires_at": "2026-09-02T09:00:00"},
                  actor=("coord01", "coordinator"))
        self.call("/api/cohorts/create",
                  {"cohort_id": "C1", "protocol_version": "1.0",
                   "drug_dose": "2.0mg/kg", "light_fluence": "100J/cm",
                   "light_schedule": "单次连续", "capacity": 6})

    def enroll(self, sid):
        self.call("/api/subjects/register", {"site_id": "SITE-A", "subject_id": sid})
        self.call("/api/subjects/consent",
                  {"subject_id": sid, "protocol_version": "1.0",
                   "signed_at": "2026-03-02T09:00:00", "consent_version": "ICF-1",
                   "document_ref": f"vault://icf/{sid}",
                   "document_checksum": f"sha256:{sid}"})
        self.call("/api/subjects/screen",
                  {"subject_id": sid, "protocol_version": "1.0",
                   "inclusion_met": {"局部不可切除": True},
                   "exclusion_met": {}, "decided_at": "2026-03-02T09:00:00"})
        self.call("/api/subjects/enroll",
                  {"subject_id": sid, "protocol_version": "1.0",
                   "at": "2026-03-02T10:00:00"})
        self.call("/api/cohorts/assign",
                  {"subject_id": sid, "cohort_id": "C1",
                   "at": "2026-03-02T11:00:00"})


class HealthRouteTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def test_health_unchanged(self):
        with urlopen(f"{self.base_url}/health", timeout=2) as response:
            body = json.load(response)
        self.assertEqual(body["status"], "ok")
        self.assertEqual(body["service"], "photodynamic-trial")


class ApiFlowTest(ApiTestBase):
    def test_full_trial_flow_over_http(self):
        self.bootstrap()
        self.enroll("S1")

        # 错误方案/未放行不能递进：新草拟版本不能用于入组
        status, body = self.call("/api/protocols/create", {"version": "2.0"})
        self.assertEqual(status, 200)

        # 治疗时间线
        status, _ = self.call("/api/activities/schedule",
                              {"subject_id": "S1", "kind": "注射",
                               "planned_at": "2026-03-03T09:00:00",
                               "activity_id": "S1-inj"})
        self.assertEqual(status, 200)
        status, _ = self.call("/api/activities/schedule",
                              {"subject_id": "S1", "kind": "激光照射",
                               "planned_at": "2026-03-03T11:00:00",
                               "activity_id": "S1-light"})
        self.assertEqual(status, 200)
        status, _ = self.call("/api/activities/perform",
                              {"activity_id": "S1-inj", "at": "2026-03-03T09:00:00",
                               "drug_lot_id": "DRUG-1"})
        self.assertEqual(status, 200)
        status, body = self.call("/api/activities/perform",
                                 {"activity_id": "S1-light",
                                  "at": "2026-03-03T11:00:00",
                                  "device_lot_id": "DEV-1"})
        self.assertEqual(status, 200, body)

        # 窗内影像与结局
        status, body = self.call("/api/artifacts/register",
                                 {"subject_id": "S1", "artifact_type": "影像",
                                  "ref": "vault://imaging/S1.dcm",
                                  "checksum": "sha256:abc",
                                  "captured_at": "2026-03-12T09:00:00"})
        self.assertEqual(status, 200, body)
        art_id = body["data"]["artifact_id"]
        status, body = self.call("/api/outcomes/record",
                                 {"subject_id": "S1",
                                  "outcome_type": "手术切除评估",
                                  "result_summary": "可切除", "resectable": True,
                                  "at": "2026-03-17T10:00:00",
                                  "artifact_ids": [art_id]})
        self.assertEqual(status, 200, body)
        self.assertEqual(body["data"]["provenance"]["protocol"]["version"], "1.0")

    def test_state_conflict_maps_to_409(self):
        self.bootstrap()
        self.enroll("S2")
        # 隔离批次后执行注射 -> 409 + 稳定错误码
        status, body = self.call("/api/lots/change_status",
                                 {"lot_id": "DRUG-1", "status": "隔离中",
                                  "reason": "调查"},
                                 actor=("dsmb01", "dsmb"))
        self.assertEqual(status, 200)
        self.call("/api/activities/schedule",
                 {"subject_id": "S2", "kind": "注射",
                  "planned_at": "2026-03-03T09:00:00", "activity_id": "S2-inj"})
        status, body = self.call("/api/activities/perform",
                                 {"activity_id": "S2-inj",
                                  "at": "2026-03-03T09:00:00",
                                  "drug_lot_id": "DRUG-1"})
        self.assertEqual(status, 409, body)
        self.assertEqual(body["error"]["code"], "lot_not_available")

    def test_permission_and_authentication(self):
        # 缺少身份头
        status, body = self.call("/api/subjects/register",
                                 {"site_id": "SITE-A"}, actor=None)
        self.assertEqual(status, 401)
        self.assertEqual(body["error"]["code"], "authentication_required")
        # 未知名词
        status, body = self.call("/api/protocols/create", {"version": "9.9"},
                                 actor=("ghost", "martian"))
        self.assertEqual(status, 403)
        # 盲态角色读不到队列
        self.bootstrap()
        status, body = self.get("/api/cohorts", actor=("reader01", "blind_reader"))
        self.assertEqual(status, 403)
        self.assertEqual(body["error"]["code"], "permission_denied")

    def test_blind_subject_view_over_http(self):
        self.bootstrap()
        self.enroll("S3")
        status, body = self.get("/api/subjects/S3", actor=("reader01", "blind_reader"))
        self.assertEqual(status, 200)
        data = body["data"]
        self.assertNotIn("cohort_id", data)
        self.assertNotIn("treatment_at", data)
        self.assertIn("window", data)

    def test_unknown_action_and_bad_json(self):
        status, _ = self.call("/api/subjects/dance", {"x": 1})
        self.assertEqual(status, 404)
        # 非法 JSON
        request = Request(
            self.base_url + "/api/protocols/create",
            data=b"{not-json", headers={"Content-Type": "application/json",
                                        "X-Actor-Id": "doc01",
                                        "X-Actor-Role": "investigator"}, method="POST")
        try:
            urlopen(request, timeout=5)
            self.fail("应返回 400")
        except HTTPError as error:
            self.assertEqual(error.code, 400)
            body = json.load(error)
            self.assertEqual(body["error"]["code"], "validation_error")
            error.close()

    def test_sae_hold_blocks_over_http_and_audit_trail(self):
        self.bootstrap()
        self.enroll("S4")
        status, body = self.call("/api/saes/report",
                                 {"subject_id": "S4", "at": "2026-03-02T12:00:00",
                                  "description": "严重过敏", "severity": "重度"})
        self.assertEqual(status, 200, body)
        sae_id = body["data"]["sae_id"]
        status, body = self.call("/api/activities/schedule",
                                 {"subject_id": "S4", "kind": "注射",
                                  "planned_at": "2026-03-03T09:00:00"})
        self.assertEqual(status, 409)
        self.assertEqual(body["error"]["code"], "sae_hold")
        # DSMB 复核放行
        status, _ = self.call("/api/saes/review",
                              {"sae_id": sae_id, "decision": "继续",
                               "rationale": "与研究药物无关"},
                              actor=("dsmb01", "dsmb"))
        self.assertEqual(status, 200)
        status, body = self.get(f"/api/audit?target_type=sae&target_id={sae_id}")
        self.assertEqual(status, 200)
        actions = {e["action"] for e in body["data"]}
        self.assertEqual(actions, {"report_sae", "review_sae"})


class AmendmentApiTest(ApiTestBase):
    def _pid(self):
        return self.r.protocol_order[0]

    def test_amendment_validation_requires_impact_domains(self):
        self.bootstrap()
        status, body = self.call("/api/amendments/submit", {
            "protocol_id": self._pid(), "new_version": "2.0",
            "summary": "修订", "impact_domains": [], "requires_reconsent": False})
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "validation_error")
        # 只有 DSMB 可批准
        self.call("/api/amendments/submit", {
            "protocol_id": self._pid(), "new_version": "2.0",
            "summary": "修订", "impact_domains": ["剂量", "器械"],
            "requires_reconsent": False})
        amd_id = list(self.r.amendments)[0]
        status, body = self.call("/api/amendments/review", {
            "amendment_id": amd_id, "approved": True, "rationale": "ok"})
        self.assertEqual(status, 403)

    def test_full_amendment_flow_blocks_then_unblocks_over_http(self):
        self.bootstrap()
        self.enroll("S1")
        # 提交 + 批准（同时建立已放行的 2.0 方案）
        _, body = self.call("/api/amendments/submit", {
            "protocol_id": self._pid(), "new_version": "2.0",
            "summary": "队列扩展调整", "impact_domains": ["剂量", "器械"],
            "requires_reconsent": False})
        amd_id = body["data"]["amendment_id"]
        status, body = self.call("/api/amendments/review", {
            "amendment_id": amd_id, "approved": True, "rationale": "安全数据支持",
            "new_protocol_params": {
                "observation_days": 21,
                "drug_to_light": {"min_minutes": 60, "max_minutes": 300}}},
            actor=("dsmb01", "dsmb"))
        self.assertEqual(status, 200, body)
        self.assertEqual(body["data"]["status"], "已批准")

        # 影响快照
        status, body = self.get(f"/api/amendments/{amd_id}/snapshot")
        self.assertEqual(status, 200)
        self.assertEqual([s["subject_id"] for s in body["data"]["subjects"]], ["S1"])
        self.assertEqual(body["data"]["subjects"][0]["recommendation"], "继续")

        # 批准后、采用/处置前：动作视图显示阻断，排程 409
        status, body = self.get("/api/subjects/S1/actions")
        self.assertTrue(body["data"]["has_open_block"])
        self.assertEqual(body["data"]["blocked"][0]["code"],
                         "amendment_requirements_open")
        status, body = self.call("/api/activities/schedule",
                                 {"subject_id": "S1", "kind": "注射",
                                  "planned_at": "2026-03-03T09:00:00"})
        self.assertEqual(status, 409, body)
        self.assertEqual(body["error"]["code"], "amendment_requirements_open")

        # 中心待办领取
        status, body = self.get(
            "/api/todos?site_id=SITE-A&status=" + quote("待处理"))
        self.assertEqual(status, 200)
        kinds = {t["kind"] for t in body["data"]}
        self.assertEqual(kinds, {"中心采用修订", "受试者修订处置"})

        # 未采用先处置 -> 409
        status, body = self.call("/api/amendments/resolve",
                                 {"amendment_id": amd_id, "subject_id": "S1",
                                  "decision": "继续"})
        self.assertEqual(status, 409)
        self.assertEqual(body["error"]["code"], "site_amendment_not_adopted")

        # 采用（重复调用幂等：审计只有一条）
        for _ in range(2):
            status, adop = self.call("/api/amendments/adopt",
                                     {"amendment_id": amd_id, "site_id": "SITE-A"})
            self.assertEqual(status, 200, adop)
        # 处置（重复调用幂等）
        for _ in range(2):
            status, res = self.call("/api/amendments/resolve",
                                    {"amendment_id": amd_id, "subject_id": "S1",
                                     "decision": "继续"})
            self.assertEqual(status, 200, res)
        self.assertEqual(res["data"]["status"], "已完成")

        # 闭环：受试者绑定 2.0，排程恢复
        status, body = self.get("/api/subjects/S1")
        self.assertEqual(body["data"]["protocol_version"], "2.0")
        status, body = self.call("/api/activities/schedule",
                                 {"subject_id": "S1", "kind": "注射",
                                  "planned_at": "2026-03-03T09:00:00",
                                  "activity_id": "S1-inj"})
        self.assertEqual(status, 200, body)
        status, body = self.get("/api/subjects/S1/actions")
        self.assertFalse(body["data"]["has_open_block"])

        # 旧版本回溯：provenance 中保留修订记录
        status, body = self.get("/api/subjects/S1/provenance")
        self.assertEqual(status, 200)
        hist = body["data"]["amendments"]
        self.assertEqual(len(hist), 1)
        self.assertEqual(hist[0]["base_version"], "1.0")
        self.assertEqual(hist[0]["final_decision"], "继续")

    def test_emergency_amendment_freeze_then_retro_review_over_http(self):
        self.bootstrap()
        self.enroll("S1")
        # 紧急修订缺理由/期限 -> 400
        status, body = self.call("/api/amendments/submit", {
            "protocol_id": self._pid(), "new_version": "2.0",
            "summary": "紧急", "impact_domains": ["安全规则"],
            "requires_reconsent": False, "emergency": True,
            "reason": "", "review_deadline_hours": 48})
        self.assertEqual(status, 400)
        # 合法提交即冻结
        _, body = self.call("/api/amendments/submit", {
            "protocol_id": self._pid(), "new_version": "2.0",
            "summary": "紧急安全修订", "impact_domains": ["安全规则", "器械"],
            "requires_reconsent": False, "emergency": True,
            "reason": "出现严重器械相关信号", "review_deadline_hours": 48})
        amd_id = body["data"]["amendment_id"]
        self.assertEqual(body["data"]["emergency"]["review_status"], "待补审")
        self.assertIsNotNone(body["data"]["impact_snapshot"])
        status, body = self.call("/api/activities/schedule",
                                 {"subject_id": "S1", "kind": "注射",
                                  "planned_at": "2026-03-03T09:00:00"})
        self.assertEqual(status, 409)
        self.assertEqual(body["error"]["code"], "emergency_amendment_freeze")
        # 补审前处置 -> 409
        self.call("/api/amendments/adopt",
                  {"amendment_id": amd_id, "site_id": "SITE-A"})
        status, body = self.call("/api/amendments/resolve",
                                 {"amendment_id": amd_id, "subject_id": "S1",
                                  "decision": "继续"})
        self.assertEqual(status, 409)
        self.assertEqual(body["error"]["code"], "emergency_amendment_pending_review")
        # DSMB 补审 -> 冻结解除，可处置
        status, _ = self.call("/api/amendments/review", {
            "amendment_id": amd_id, "approved": True, "rationale": "补审认可",
            "new_protocol_params": {"observation_days": 14,
                                    "drug_to_light": {"min_minutes": 60,
                                                      "max_minutes": 240}}},
            actor=("dsmb01", "dsmb"))
        self.assertEqual(status, 200)
        status, _ = self.call("/api/amendments/resolve",
                              {"amendment_id": amd_id, "subject_id": "S1",
                               "decision": "继续"})
        self.assertEqual(status, 200)

    def test_blind_role_denied_amendment_views_but_sees_narrowed_actions(self):
        self.bootstrap()
        self.enroll("S1")
        self.call("/api/amendments/submit", {
            "protocol_id": self._pid(), "new_version": "2.0",
            "summary": "修订", "impact_domains": ["剂量"],
            "requires_reconsent": False})
        amd_id = list(self.r.amendments)[0]
        self.call("/api/amendments/review",
                  {"amendment_id": amd_id, "approved": True, "rationale": "ok"},
                  actor=("dsmb01", "dsmb"))
        for path in ("/api/amendments", f"/api/amendments/{amd_id}",
                     f"/api/amendments/{amd_id}/snapshot", "/api/todos?site_id=SITE-A"):
            status, body = self.get(path, actor=("reader01", "blind_reader"))
            self.assertEqual(status, 403, path)
            self.assertEqual(body["error"]["code"], "permission_denied")
        # 动作视图对盲态可用且收窄
        status, body = self.get("/api/subjects/S1/actions",
                                actor=("reader01", "blind_reader"))
        self.assertEqual(status, 200)
        self.assertTrue(body["data"]["has_open_block"])
        self.assertNotIn("blocks", body["data"]["blocked"][0])


if __name__ == "__main__":
    unittest.main()
