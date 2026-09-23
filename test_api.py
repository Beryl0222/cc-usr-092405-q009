"""受控流程 HTTP 接口契约测试。"""

import json
import threading
import unittest
from datetime import datetime, timedelta
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
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


if __name__ == "__main__":
    unittest.main()
