"""方案修订（队列扩展）受控流程测试。

验收输入覆盖：多中心不同采用顺序、期限推进、并发确认幂等、请求顺序无关，
以及撤回同意/未关闭 SAE/盲态限制的优先级与旧版本回溯。
"""

import threading
import unittest
from datetime import datetime, timedelta

from trial import (
    NotFoundError,
    PermissionDeniedError,
    StateConflictError,
    TrialError,
    TrialRegistry,
    ValidationError,
)

INVESTIGATOR = {"id": "doc01", "role": "研究者"}
COORDINATOR = {"id": "coord01", "role": "试验协调员"}
DSMB = {"id": "dsmb01", "role": "安全委员会"}
BLIND = {"id": "reader01", "role": "盲态评价者"}

T0 = datetime(2026, 3, 2, 9, 0)


class Clock:
    def __init__(self, t=T0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, **kwargs):
        self.t += timedelta(**kwargs)
        return self.t


class AmendmentTestBase(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.r = TrialRegistry(clock=self.clock)
        self._bootstrap()

    def _bootstrap(self, *, sites=("SITE-A", "SITE-B")):
        self.proto = self.r.create_protocol(
            INVESTIGATOR, version="1.0",
            drug_to_light_min_minutes=60, drug_to_light_max_minutes=240,
        )
        self.pid = self.proto["protocol_id"]
        self.r.submit_protocol_for_approval(INVESTIGATOR, self.pid)
        self.r.approve_protocol(DSMB, self.pid, decision="继续", rationale="放行")
        for site in sites:
            self.r.register_site(
                COORDINATOR, site_id=site, name="中心" + site,
                credentials_expire_at=self.clock.t + timedelta(days=365),
            )
            self.r.review_site_credentials(
                COORDINATOR, site, approved=True,
                qualified_versions=["1.0"], rationale="资质齐全",
            )
        self.r.register_lot(
            COORDINATOR, lot_id="DRUG-1", kind="药物", product="光敏剂A",
            expires_at=self.clock.t + timedelta(days=180),
        )
        self.r.register_lot(
            COORDINATOR, lot_id="DEV-1", kind="器械", product="激光光纤球囊",
            expires_at=self.clock.t + timedelta(days=180),
        )
        for cid, dose, fluence in (("Q1", "2.0mg/kg", "100J/cm"),
                                   ("Q2", "4.0mg/kg", "200J/cm")):
            self.r.create_cohort(
                INVESTIGATOR, cohort_id=cid, protocol_version="1.0",
                drug_dose=dose, light_fluence=fluence,
                light_schedule="单次连续", capacity=20,
            )

    def enroll(self, sid, *, site="SITE-A", cohort="Q1"):
        self.r.register_subject(INVESTIGATOR, site_id=site, subject_id=sid)
        self.r.record_consent(
            INVESTIGATOR, subject_id=sid, protocol_version="1.0",
            signed_at=self.clock.t, consent_version="ICF-1",
            document_ref="vault://icf/" + sid,
            document_checksum="sha256:icf-" + sid,
        )
        self.r.screen_eligibility(
            INVESTIGATOR, subject_id=sid, protocol_version="1.0",
            inclusion_met={"局部不可切除": True}, exclusion_met={},
            decided_at=self.clock.t,
        )
        self.r.enroll_subject(
            INVESTIGATOR, subject_id=sid, protocol_version="1.0",
            at=self.clock.t + timedelta(hours=1),
        )
        self.r.assign_cohort(
            INVESTIGATOR, subject_id=sid, cohort_id=cohort,
            at=self.clock.t + timedelta(hours=2),
        )

    def inject(self, sid, *, hours=24):
        aid = f"{sid}-inj"
        self.r.schedule_activity(
            INVESTIGATOR, subject_id=sid, kind="注射",
            planned_at=self.clock.t + timedelta(hours=hours), activity_id=aid,
        )
        self.r.perform_activity(
            INVESTIGATOR, activity_id=aid,
            at=self.clock.t + timedelta(hours=hours), drug_lot_id="DRUG-1",
        )

    def schedule_light(self, sid, *, hours=26, suffix="l"):
        aid = f"{sid}-{suffix}"
        self.r.schedule_activity(
            INVESTIGATOR, subject_id=sid, kind="激光照射",
            planned_at=self.clock.t + timedelta(hours=hours), activity_id=aid,
        )
        return aid

    def light(self, sid, *, hours=26, suffix="l"):
        aid = self.schedule_light(sid, hours=hours, suffix=suffix)
        self.r.perform_activity(
            INVESTIGATOR, activity_id=aid,
            at=self.clock.t + timedelta(hours=hours), device_lot_id="DEV-1",
        )
        return aid

    def submit_review_adopt(self, *, new_version, impact, site="SITE-A",
                            emergency=False, review_due_at=None):
        amd = self.r.submit_amendment(
            INVESTIGATOR, protocol_id=self.pid, new_version=new_version,
            impact=impact, rationale=f"修订 {new_version}",
            emergency=emergency,
            review_due_at=review_due_at or (self.clock.t + timedelta(days=2)),
        )
        if not emergency:
            out = self.r.review_amendment(
                DSMB, amd["amendment_id"], decision="批准", rationale="DSMB 认可")
        else:
            out = amd
        if site is not None and out["status"] == "已批准":
            self.r.adopt_amendment_at_site(
                INVESTIGATOR, amendment_id=amd["amendment_id"], site_id=site,
            )
        return amd["amendment_id"]

    def approve_and_adopt(self, aid, *, site="SITE-A", decision="批准"):
        out = self.r.review_amendment(DSMB, aid, decision=decision, rationale="复核")
        if decision == "批准":
            self.r.adopt_amendment_at_site(
                INVESTIGATOR, amendment_id=aid, site_id=site,
            )
        return out

    def todo_map(self, *, site="SITE-A"):
        return {t["subject_id"]: t for t in self.r.list_site_todos(INVESTIGATOR, site)}


class AmendmentSubmissionTest(AmendmentTestBase):
    def test_impact_domains_validated(self):
        with self.assertRaisesRegex(ValidationError, "影响面"):
            self.r.submit_amendment(
                INVESTIGATOR, protocol_id=self.pid, new_version="1.1",
                impact={"未知域": {}}, rationale="x")
        with self.assertRaisesRegex(ValidationError, "至少一个影响面"):
            self.r.submit_amendment(
                INVESTIGATOR, protocol_id=self.pid, new_version="1.1",
                impact={}, rationale="x")
        with self.assertRaisesRegex(ValidationError, "理由"):
            self.r.submit_amendment(
                INVESTIGATOR, protocol_id=self.pid, new_version="1.1",
                impact={"剂量": {"x": 1}}, rationale="  ")

    def test_only_dsmb_reviews_and_normal_amendment_does_not_freeze(self):
        amd = self.r.submit_amendment(
            INVESTIGATOR, protocol_id=self.pid, new_version="1.1",
            impact={"器械": {"lot": "DEV-2"}}, rationale="升级")
        self.assertEqual(amd["status"], "待复核")
        self.assertFalse(amd["overdue"])
        self.enroll("S1")
        # 待复核期间不冻结既有操作
        act = self.r.schedule_activity(
            INVESTIGATOR, subject_id="S1", kind="影像采集",
            planned_at=self.clock.t + timedelta(days=3))
        self.assertEqual(act["status"], "已排程")
        with self.assertRaises(PermissionDeniedError):
            self.r.review_amendment(
                INVESTIGATOR, amd["amendment_id"], decision="批准", rationale="研究者")
        # 批准前中心不得采用
        with self.assertRaisesRegex(StateConflictError, "尚未获安全委员会批准") as cm:
            self.r.adopt_amendment_at_site(
                INVESTIGATOR, amendment_id=amd["amendment_id"], site_id="SITE-A")
        self.assertEqual(cm.exception.code, "amendment_not_approved")

    def test_emergency_requires_due_and_freezes_immediately(self):
        with self.assertRaisesRegex(ValidationError, "补审期限"):
            self.r.submit_amendment(
                INVESTIGATOR, protocol_id=self.pid, new_version="2.0",
                impact={"安全规则": {"rule": "x"}}, rationale="r", emergency=True)
        with self.assertRaisesRegex(ValidationError, "晚于当前时间"):
            self.r.submit_amendment(
                INVESTIGATOR, protocol_id=self.pid, new_version="2.0",
                impact={"安全规则": {"rule": "x"}}, rationale="r",
                emergency=True, review_due_at=self.clock.t - timedelta(hours=1))
        self.enroll("S1")
        amd = self.r.submit_amendment(
            INVESTIGATOR, protocol_id=self.pid, new_version="2.0",
            impact={"安全规则": {"rule": "加强监测"}}, rationale="急性毒性信号",
            emergency=True, review_due_at=self.clock.t + timedelta(days=2))
        self.assertEqual(amd["status"], "冻结生效中")
        with self.assertRaises(StateConflictError) as cm:
            self.r.schedule_activity(
                INVESTIGATOR, subject_id="S1", kind="注射",
                planned_at=self.clock.t + timedelta(hours=24))
        self.assertEqual(cm.exception.code, "amendment_freeze")

    def test_rejected_amendment_does_not_create_version_or_freeze(self):
        amd = self.r.submit_amendment(
            INVESTIGATOR, protocol_id=self.pid, new_version="9.0",
            impact={"安全规则": {"x": 1}}, rationale="r")
        out = self.r.review_amendment(
            DSMB, amd["amendment_id"], decision="驳回", rationale="证据不足")
        self.assertEqual(out["status"], "已驳回")
        self.assertIsNone(out["new_protocol_id"])
        versions = {p["version"] for p in self.r.protocols.values()}
        self.assertNotIn("9.0", versions)
        with self.assertRaisesRegex(StateConflictError, "尚未获安全委员会批准"):
            self.r.adopt_amendment_at_site(
                INVESTIGATOR, amendment_id=amd["amendment_id"], site_id="SITE-A")
        with self.assertRaisesRegex(StateConflictError, "批准后"):
            self.r.amendment_snapshots(DSMB, amd["amendment_id"])


class SnapshotDecisionMatrixTest(AmendmentTestBase):
    def _approved_decisions(self, aid):
        return {row["subject_id"]: row["decision"]
                for row in self.r.amendment_snapshots(DSMB, aid)}

    def test_device_impact_decisions_by_treatment_facts(self):
        # 未治疗 / 已注射待照光（有待执行照光）/ 已照光
        self.enroll("FRESH")
        self.enroll("MID")
        self.inject("MID")
        self.schedule_light("MID")
        self.enroll("DONE")
        self.inject("DONE")
        self.light("DONE")
        aid = self.r.submit_amendment(
            INVESTIGATOR, protocol_id=self.pid, new_version="1.1",
            impact={"器械": {"required_lot": "DEV-2"}}, rationale="换器械")["amendment_id"]
        self.r.review_amendment(DSMB, aid, decision="批准", rationale="ok")
        decisions = self._approved_decisions(aid)
        self.assertEqual(decisions["FRESH"], "补充同意")
        self.assertEqual(decisions["MID"], "重新排程")
        self.assertEqual(decisions["DONE"], "继续")

    def test_dose_impact_cohort_scoped_and_injection_boundary(self):
        self.enroll("Q1-FRESH", cohort="Q1")
        self.enroll("Q1-INJ", cohort="Q1")
        self.inject("Q1-INJ")
        self.enroll("Q1-LIT", cohort="Q1")
        self.inject("Q1-LIT")
        self.light("Q1-LIT")
        self.enroll("Q2-FRESH", cohort="Q2")
        aid = self.r.submit_amendment(
            INVESTIGATOR, protocol_id=self.pid, new_version="1.2",
            impact={"剂量": {"cohorts": ["Q1"], "drug_dose": "3.0mg/kg"}},
            rationale="扩展剂量队列")["amendment_id"]
        self.r.review_amendment(DSMB, aid, decision="批准", rationale="ok")
        decisions = self._approved_decisions(aid)
        self.assertEqual(decisions["Q1-FRESH"], "补充同意")
        self.assertEqual(decisions["Q1-INJ"], "退出")
        self.assertEqual(decisions["Q1-LIT"], "继续")
        # Q2 不在选择器内：不受影响
        self.assertEqual(decisions["Q2-FRESH"], "继续")

    def test_safety_rule_impact_requires_reconsent_for_all_active(self):
        self.enroll("A")
        self.enroll("B")
        self.inject("B")
        aid = self.r.submit_amendment(
            INVESTIGATOR, protocol_id=self.pid, new_version="1.3",
            impact={"安全规则": {"monitoring": "加测肝功能"}}, rationale="安全信号")["amendment_id"]
        self.r.review_amendment(DSMB, aid, decision="批准", rationale="ok")
        decisions = self._approved_decisions(aid)
        self.assertEqual(decisions["A"], "补充同意")
        self.assertEqual(decisions["B"], "补充同意")

    def test_observation_window_impact(self):
        self.enroll("PRE")
        self.enroll("POST")
        self.inject("POST")
        self.light("POST")
        aid = self.r.submit_amendment(
            INVESTIGATOR, protocol_id=self.pid, new_version="1.4",
            impact={"观察窗口": {"days": 21}}, rationale="延长评估")["amendment_id"]
        self.r.review_amendment(DSMB, aid, decision="批准", rationale="ok")
        decisions = self._approved_decisions(aid)
        self.assertEqual(decisions["PRE"], "补充同意")
        self.assertEqual(decisions["POST"], "继续")

    def test_withdrawn_subject_has_no_decision_but_kept_in_snapshot(self):
        self.enroll("W")
        self.r.withdraw_consent(
            INVESTIGATOR, subject_id="W", at=self.clock.t + timedelta(hours=3),
            reason="个人原因")
        aid = self.r.submit_amendment(
            INVESTIGATOR, protocol_id=self.pid, new_version="1.1",
            impact={"器械": {"x": 1}}, rationale="r")["amendment_id"]
        self.r.review_amendment(DSMB, aid, decision="批准", rationale="ok")
        row = next(r for r in self.r.amendment_snapshots(DSMB, aid)
                   if r["subject_id"] == "W")
        self.assertTrue(row["withdrawn"])
        self.assertIsNone(row["decision"])


class SiteAdoptionTest(AmendmentTestBase):
    def _two_site_amendment(self, new_version="1.1", impact=None):
        self.enroll("A1", site="SITE-A")
        self.enroll("A2", site="SITE-A")
        self.inject("A2")
        self.enroll("B1", site="SITE-B")
        aid = self.r.submit_amendment(
            INVESTIGATOR, protocol_id=self.pid, new_version=new_version,
            impact=impact or {"器械": {"lot": "DEV-2"}}, rationale="r")["amendment_id"]
        self.r.review_amendment(DSMB, aid, decision="批准", rationale="ok")
        return aid

    def test_sites_adopt_in_different_orders_with_identical_results(self):
        aid = self._two_site_amendment()
        # B 中心先采用
        self.r.adopt_amendment_at_site(
            INVESTIGATOR, amendment_id=aid, site_id="SITE-B")
        b_todos = self.r.list_site_todos(INVESTIGATOR, "SITE-B")
        self.assertEqual([t["subject_id"] for t in b_todos], ["B1"])
        # A 中心只能领到自己的待办
        self.assertEqual(self.r.list_site_todos(INVESTIGATOR, "SITE-A"), [])
        # A 后采用，结论与“同时采用”完全一致
        self.r.adopt_amendment_at_site(
            INVESTIGATOR, amendment_id=aid, site_id="SITE-A")
        a_required = {t["subject_id"]: t["required_resolution"]
                      for t in self.r.list_site_todos(INVESTIGATOR, "SITE-A")}
        self.assertEqual(a_required, {"A1": "补充同意", "A2": "重新排程"})
        # B 不受 A 采用影响
        self.assertEqual(len(self.r.list_site_todos(INVESTIGATOR, "SITE-B")), 1)

    def test_adoption_is_idempotent_under_concurrent_calls(self):
        aid = self._two_site_amendment()
        results: list[object] = []
        errors: list[BaseException] = []
        lock = threading.Lock()

        def adopt():
            try:
                out = self.r.adopt_amendment_at_site(
                    INVESTIGATOR, amendment_id=aid, site_id="SITE-A")
                with lock:
                    results.append(out["todo_ids"])
            except BaseException as exc:  # noqa: BLE001
                with lock:
                    errors.append(exc)

        threads = [threading.Thread(target=adopt) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        self.assertEqual(len(results), 8)
        first = results[0]
        for item in results[1:]:
            self.assertEqual(item, first)
        # 待办只生成一次
        self.assertEqual(len(self.r.list_site_todos(INVESTIGATOR, "SITE-A")), 2)

    def test_adoption_extends_site_version_qualification(self):
        aid = self._two_site_amendment()
        self.assertNotIn("1.1", self.r.sites["SITE-A"]["qualified_versions"])
        self.r.adopt_amendment_at_site(
            INVESTIGATOR, amendment_id=aid, site_id="SITE-A")
        self.assertIn("1.1", self.r.sites["SITE-A"]["qualified_versions"])
        view = self.r.get_amendment(DSMB, aid)
        self.assertEqual(view["adopting_site_ids"], ["SITE-A"])
        self.r.adopt_amendment_at_site(
            INVESTIGATOR, amendment_id=aid, site_id="SITE-B")
        view = self.r.get_amendment(DSMB, aid)
        self.assertEqual(view["adopting_site_ids"], ["SITE-A", "SITE-B"])

    def test_suspended_site_cannot_adopt(self):
        aid = self._two_site_amendment()
        self.r.change_site_status(
            COORDINATOR, "SITE-B", status="已暂停", reason="稽查发现")
        with self.assertRaisesRegex(StateConflictError, "不得采用新版本") as cm:
            self.r.adopt_amendment_at_site(
                INVESTIGATOR, amendment_id=aid, site_id="SITE-B")
        self.assertEqual(cm.exception.code, "site_not_qualified")

    def test_decision_drift_marked_when_facts_advance_between_review_and_adopt(self):
        self.enroll("D")
        aid = self.r.submit_amendment(
            INVESTIGATOR, protocol_id=self.pid, new_version="1.1",
            impact={"器械": {"lot": "DEV-2"}}, rationale="r")["amendment_id"]
        self.r.review_amendment(DSMB, aid, decision="批准", rationale="ok")
        # 批准快照时 D 尚未治疗 -> 补充同意
        snap = next(s for s in self.r.amendment_snapshots(DSMB, aid)
                    if s["subject_id"] == "D")
        self.assertEqual(snap["decision"], "补充同意")
        # 采用前完成注射并排程照光 -> 采用时事实变为“重新排程”
        self.inject("D")
        self.schedule_light("D")
        self.r.adopt_amendment_at_site(
            INVESTIGATOR, amendment_id=aid, site_id="SITE-A")
        todo = self.todo_map()["D"]
        self.assertTrue(todo["decision_drift"])
        self.assertEqual(todo["approved_decision"], "补充同意")
        self.assertEqual(todo["required_resolution"], "重新排程")


class TodoResolutionBlockingTest(AmendmentTestBase):
    def test_operations_blocked_until_resolution_and_resume_after(self):
        self.enroll("S1")
        aid = self.submit_review_adopt(
            new_version="1.1", impact={"安全规则": {"rule": "加测"}})
        todo = self.todo_map()["S1"]
        for fn in (
            lambda: self.r.schedule_activity(
                INVESTIGATOR, subject_id="S1", kind="注射",
                planned_at=self.clock.t + timedelta(hours=24)),
            lambda: self.r.schedule_activity(
                INVESTIGATOR, subject_id="S1", kind="访视",
                planned_at=self.clock.t + timedelta(days=2)),
            lambda: self.r.register_artifact(
                INVESTIGATOR, subject_id="S1", artifact_type="影像",
                ref="u", checksum="h", captured_at=self.clock.t + timedelta(days=2)),
            lambda: self.r.record_outcome(
                INVESTIGATOR, subject_id="S1", outcome_type="影像评估",
                result_summary="x", at=self.clock.t + timedelta(days=2)),
        ):
            with self.assertRaisesRegex(StateConflictError, "待处置") as cm:
                fn()
            self.assertEqual(cm.exception.code, "amendment_requirement_open")
        # 未补同意不能完成待办
        with self.assertRaisesRegex(StateConflictError, "重新签署知情同意"):
            self.r.resolve_amendment_todo(
                INVESTIGATOR, todo_id=todo["todo_id"], resolution="补充同意")
        # 补签新版同意（必须与新版本一致）
        with self.assertRaises(ValidationError):
            self.r.record_consent(
                INVESTIGATOR, subject_id="S1", protocol_version="1.0",
                signed_at=self.clock.t, consent_version="ICF-2",
                document_ref="u2", document_checksum="h2", amendment_id=aid)
        self.r.record_consent(
            INVESTIGATOR, subject_id="S1", protocol_version="1.1",
            signed_at=self.clock.t, consent_version="ICF-2",
            document_ref="u2", document_checksum="h2", amendment_id=aid)
        self.r.resolve_amendment_todo(
            INVESTIGATOR, todo_id=todo["todo_id"], resolution="补充同意")
        # 阻断解除
        act = self.r.schedule_activity(
            INVESTIGATOR, subject_id="S1", kind="访视",
            planned_at=self.clock.t + timedelta(days=2))
        self.assertEqual(act["status"], "已排程")

    def test_reschedule_requires_evidence_and_exit_always_allowed(self):
        self.enroll("S1")
        self.inject("S1")
        light = self.schedule_light("S1")
        aid = self.submit_review_adopt(
            new_version="1.1", impact={"器械": {"lot": "DEV-2"}})
        todo = self.todo_map()["S1"]
        self.assertEqual(todo["required_resolution"], "重新排程")
        # 错误处置被拒绝（退出始终允许）
        with self.assertRaisesRegex(StateConflictError, "治疗事实要求") as cm:
            self.r.resolve_amendment_todo(
                INVESTIGATOR, todo_id=todo["todo_id"], resolution="补充同意")
        self.assertEqual(cm.exception.code, "todo_resolution_mismatch")
        with self.assertRaisesRegex(StateConflictError, "改期"):
            self.r.resolve_amendment_todo(
                INVESTIGATOR, todo_id=todo["todo_id"], resolution="重新排程")
        # delay 携带 amendment_id 作为证据
        self.r.delay_activity(
            INVESTIGATOR, activity_id=light,
            new_planned_at=self.clock.t + timedelta(hours=29),
            reason="等待新器械", amendment_id=aid)
        out = self.r.resolve_amendment_todo(
            INVESTIGATOR, todo_id=todo["todo_id"], resolution="重新排程")
        self.assertEqual(out["status"], "已完成")
        self.assertEqual(out["resolution"]["rescheduled_activity_ids"], [light])

    def test_schedule_with_amendment_id_is_also_reschedule_evidence(self):
        self.enroll("S2")
        self.inject("S2")
        aid = self.submit_review_adopt(
            new_version="1.1", impact={"器械": {"lot": "DEV-2"}})
        todo = self.todo_map()["S2"]
        # 常规排程仍被阻断
        with self.assertRaisesRegex(StateConflictError, "待处置"):
            self.r.schedule_activity(
                INVESTIGATOR, subject_id="S2", kind="激光照射",
                planned_at=self.clock.t + timedelta(hours=30))
        # 携带修订的新建排程放行并成为证据
        act = self.r.schedule_activity(
            INVESTIGATOR, subject_id="S2", kind="激光照射",
            planned_at=self.clock.t + timedelta(hours=30),
            activity_id="S2-l-new", amendment_id=aid)
        self.assertEqual(act["amendment_id"], aid)
        out = self.r.resolve_amendment_todo(
            INVESTIGATOR, todo_id=todo["todo_id"], resolution="重新排程")
        self.assertEqual(out["resolution"]["rescheduled_activity_ids"],
                         ["S2-l-new"])

    def test_concurrent_confirmations_are_idempotent_and_conflict_free(self):
        self.enroll("S1")
        aid = self.submit_review_adopt(
            new_version="1.1", impact={"安全规则": {"rule": "x"}})
        todo = self.todo_map()["S1"]
        self.r.record_consent(
            INVESTIGATOR, subject_id="S1", protocol_version="1.1",
            signed_at=self.clock.t, consent_version="ICF-2",
            document_ref="u", document_checksum="h", amendment_id=aid)
        outcomes: list[str] = []
        errors: list[BaseException] = []
        lock = threading.Lock()

        def confirm():
            try:
                out = self.r.resolve_amendment_todo(
                    INVESTIGATOR, todo_id=todo["todo_id"], resolution="补充同意")
                with lock:
                    outcomes.append(out["resolved_at"])
            except BaseException as exc:  # noqa: BLE001
                with lock:
                    errors.append(exc)

        threads = [threading.Thread(target=confirm) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        self.assertEqual(len(set(outcomes)), 1)  # 全部返回同一完成时间
        self.assertEqual(len(outcomes), 10)

    def test_different_concurrent_resolutions_conflict_deterministically(self):
        self.enroll("S1")
        self.inject("S1")
        self.schedule_light("S1")
        aid = self.submit_review_adopt(
            new_version="1.1", impact={"器械": {"lot": "DEV-2"}})
        todo_id = self.todo_map()["S1"]["todo_id"]
        barrier = threading.Barrier(2)
        results: list[str] = []
        lock = threading.Lock()
        conflict_codes = {
            "todo_resolution_conflict", "amendment_reschedule_required"}

        def run(resolution, do_delay=False):
            try:
                barrier.wait()
                if do_delay:
                    self.r.delay_activity(
                        INVESTIGATOR, activity_id="S1-l",
                        new_planned_at=self.clock.t + timedelta(hours=29),
                        reason="r", amendment_id=aid)
                self.r.resolve_amendment_todo(
                    INVESTIGATOR, todo_id=todo_id, resolution=resolution)
                with lock:
                    results.append("ok:" + resolution)
            except StateConflictError as exc:
                with lock:
                    results.append("err:" + exc.code)

        t1 = threading.Thread(target=run, args=("重新排程", True))
        t2 = threading.Thread(target=run, args=("退出", False))
        t1.start(); t2.start(); t1.join(); t2.join()
        oks = [x for x in results if x.startswith("ok:")]
        errs = [x[4:] for x in results if x.startswith("err:")]
        self.assertEqual(len(oks), 1, results)          # 恰一个处置落库
        self.assertTrue(all(c in conflict_codes for c in errs), results)
        self.assertEqual(self.r.amendment_todos[todo_id]["status"], "已完成")

    def test_arrival_order_gives_same_conflict_semantics(self):
        # 顺序 A：先退出再尝试重排确认 -> 冲突
        def fresh():
            self.setUp()
            self.enroll("S1")
            self.inject("S1")
            self.schedule_light("S1")
            aid = self.submit_review_adopt(
                new_version="1.1", impact={"器械": {"lot": "DEV-2"}})
            return self.todo_map()["S1"]["todo_id"], aid

        todo_id, _ = fresh()
        self.r.resolve_amendment_todo(
            INVESTIGATOR, todo_id=todo_id, resolution="退出")
        with self.assertRaisesRegex(StateConflictError, "已按 退出") as cm:
            self.r.resolve_amendment_todo(
                INVESTIGATOR, todo_id=todo_id, resolution="重新排程")
        self.assertEqual(cm.exception.code, "todo_resolution_conflict")

        # 顺序 B：先完成重排再尝试退出 -> 同样稳定冲突
        todo_id2, aid2 = fresh()
        self.r.delay_activity(
            INVESTIGATOR, activity_id="S1-l",
            new_planned_at=self.clock.t + timedelta(hours=29),
            reason="r", amendment_id=aid2)
        self.r.resolve_amendment_todo(
            INVESTIGATOR, todo_id=todo_id2, resolution="重新排程")
        with self.assertRaisesRegex(StateConflictError, "已按 重新排程") as cm:
            self.r.resolve_amendment_todo(
                INVESTIGATOR, todo_id=todo_id2, resolution="退出")
        self.assertEqual(cm.exception.code, "todo_resolution_conflict")


class EmergencyAmendmentTest(AmendmentTestBase):
    def test_freeze_blocks_all_research_but_not_sae_or_withdrawal(self):
        self.enroll("S1")
        amd = self.r.submit_amendment(
            INVESTIGATOR, protocol_id=self.pid, new_version="2.0",
            impact={"安全规则": {"rule": "暂停一切暴露"}}, rationale="死亡事件",
            emergency=True, review_due_at=self.clock.t + timedelta(days=1))
        with self.assertRaises(StateConflictError) as cm:
            self.r.schedule_activity(
                INVESTIGATOR, subject_id="S1", kind="注射",
                planned_at=self.clock.t + timedelta(hours=24))
        self.assertEqual(cm.exception.code, "amendment_freeze")
        # 紧急偏离不能绕过修订冻结
        with self.assertRaises(StateConflictError) as cm:
            self.r.declare_emergency_deviation(
                INVESTIGATOR, subject_id="S1", at=self.clock.t,
                deviation_type="治疗前紧急处置", reason="抢救",
                target_kind="激光照射",
                target_planned_at=self.clock.t + timedelta(hours=1))
        self.assertEqual(cm.exception.code, "amendment_freeze")
        # SAE 与撤回不被冻结拦截
        sae = self.r.report_sae(
            INVESTIGATOR, subject_id="S1", at=self.clock.t,
            description="监测中事件", severity="中度")
        self.assertIn(sae["sae_id"], self.r.saes)
        self.r.withdraw_consent(
            INVESTIGATOR, subject_id="S1", at=self.clock.t + timedelta(hours=1))
        self.assertTrue(self.r.subjects["S1"]["withdrawn"])

    def test_freeze_blocks_new_enrollment(self):
        self.r.submit_amendment(
            INVESTIGATOR, protocol_id=self.pid, new_version="2.0",
            impact={"安全规则": {"x": 1}}, rationale="r",
            emergency=True, review_due_at=self.clock.t + timedelta(days=1))
        self.r.register_subject(INVESTIGATOR, site_id="SITE-A", subject_id="NEW")
        self.r.record_consent(
            INVESTIGATOR, subject_id="NEW", protocol_version="1.0",
            signed_at=self.clock.t, consent_version="I",
            document_ref="u", document_checksum="h")
        self.r.screen_eligibility(
            INVESTIGATOR, subject_id="NEW", protocol_version="1.0",
            inclusion_met={"a": True}, exclusion_met={}, decided_at=self.clock.t)
        with self.assertRaises(StateConflictError) as cm:
            self.r.enroll_subject(
                INVESTIGATOR, subject_id="NEW", protocol_version="1.0",
                at=self.clock.t + timedelta(hours=1))
        self.assertEqual(cm.exception.code, "amendment_freeze")

    def test_overdue_ratify_is_marked_and_freeze_never_auto_lifts(self):
        self.enroll("S1")
        due = self.clock.t + timedelta(days=1)
        amd = self.r.submit_amendment(
            INVESTIGATOR, protocol_id=self.pid, new_version="2.0",
            impact={"安全规则": {"x": 1}}, rationale="r",
            emergency=True, review_due_at=due)
        self.clock.advance(days=2)
        view = self.r.get_amendment(DSMB, amd["amendment_id"])
        self.assertTrue(view["overdue"])
        # 逾期后冻结仍在（fail-safe，不自动解除）
        with self.assertRaises(StateConflictError) as cm:
            self.r.schedule_activity(
                INVESTIGATOR, subject_id="S1", kind="访视",
                planned_at=self.clock.t)
        self.assertEqual(cm.exception.code, "amendment_freeze")
        out = self.r.review_amendment(
            DSMB, amd["amendment_id"], decision="批准", rationale="逾期补审认可")
        self.assertTrue(out["review"]["ratified_late"])
        # 补审通过后冻结解除（尚未采用，无逐人待办）
        act = self.r.schedule_activity(
            INVESTIGATOR, subject_id="S1", kind="访视",
            planned_at=self.clock.t, activity_id="S1-v")
        self.assertEqual(act["status"], "已排程")

    def test_due_progress_flags_site_todos(self):
        self.enroll("S1")
        # 普通修订也可以声明中心处置期限；与补审期限相互独立
        amd = self.r.submit_amendment(
            INVESTIGATOR, protocol_id=self.pid, new_version="1.5",
            impact={"安全规则": {"x": 1}}, rationale="r",
            site_action_due_at=self.clock.t + timedelta(days=1))
        self.assertEqual(amd["status"], "待复核")
        self.r.review_amendment(
            DSMB, amd["amendment_id"], decision="批准", rationale="ok")
        self.r.adopt_amendment_at_site(
            INVESTIGATOR, amendment_id=amd["amendment_id"], site_id="SITE-A")
        todo = self.r.list_site_todos(INVESTIGATOR, "SITE-A")[0]
        self.assertFalse(todo["overdue"])
        self.clock.advance(days=2)
        todo = self.r.list_site_todos(INVESTIGATOR, "SITE-A")[0]
        self.assertTrue(todo["overdue"])


class PriorityTest(AmendmentTestBase):
    def test_open_sae_outranks_amendment_blocks(self):
        self.enroll("S1")
        self.submit_review_adopt(
            new_version="1.1", impact={"安全规则": {"x": 1}})
        self.r.report_sae(
            INVESTIGATOR, subject_id="S1", at=self.clock.t + timedelta(hours=3),
            description="事件", severity="重度")
        actions = self.r.subject_available_actions(INVESTIGATOR, "S1")
        self.assertEqual(actions["blocking_reasons"][0]["code"], "sae_hold")
        # 操作报错也是 SAE 优先
        with self.assertRaisesRegex(StateConflictError, "SAE") as cm:
            self.r.schedule_activity(
                INVESTIGATOR, subject_id="S1", kind="注射",
                planned_at=self.clock.t + timedelta(hours=24))
        self.assertEqual(cm.exception.code, "sae_hold")

    def test_withdrawal_invalidates_open_todos_and_blocks_new_ones(self):
        self.enroll("S1")
        self.submit_review_adopt(
            new_version="1.1", impact={"安全规则": {"x": 1}})
        self.r.withdraw_consent(
            INVESTIGATOR, subject_id="S1", at=self.clock.t + timedelta(hours=3),
            reason="退出研究")
        todos = self.r.list_site_todos(INVESTIGATOR, "SITE-A")
        self.assertEqual(todos[0]["status"], "已失效")
        self.assertIn("自动失效", todos[0]["resolution"]["resolution"])
        actions = self.r.subject_available_actions(INVESTIGATOR, "S1")
        self.assertEqual(actions["blocking_reasons"][0]["code"],
                         "subject_withdrawn")
        # 已失效待办不能再确认
        with self.assertRaisesRegex(StateConflictError, "失效") as cm:
            self.r.resolve_amendment_todo(
                INVESTIGATOR, todo_id=todos[0]["todo_id"], resolution="补充同意")
        self.assertEqual(cm.exception.code, "todo_invalidated")

    def test_sae_termination_invalidates_todos(self):
        self.enroll("S1")
        self.submit_review_adopt(
            new_version="1.1", impact={"安全规则": {"x": 1}})
        sae = self.r.report_sae(
            INVESTIGATOR, subject_id="S1", at=self.clock.t + timedelta(hours=3),
            description="死亡", severity="死亡")
        self.r.review_sae(
            DSMB, sae_id=sae["sae_id"], decision="终止", rationale="终止受试者")
        todo = self.r.list_site_todos(INVESTIGATOR, "SITE-A")[0]
        self.assertEqual(todo["status"], "已失效")

    def test_blind_role_sees_only_narrowed_todo_and_actions(self):
        self.enroll("S1")
        self.submit_review_adopt(
            new_version="1.1", impact={"剂量": {"cohorts": ["Q1"]}})
        # 盲态可领运营待办，但不见剂量/影响面
        todos = self.r.list_site_todos(BLIND, "SITE-A")
        self.assertEqual(len(todos), 1)
        self.assertNotIn("decision_facts", todos[0])
        self.assertNotIn("required_resolution", todos[0])
        actions = self.r.subject_available_actions(BLIND, "S1")
        self.assertTrue(actions["blocked"])
        self.assertEqual(actions["blocking_reasons"][0],
                         {"code": "amendment_requirement_open"})
        # 盲态不可读修订实质与快照
        with self.assertRaises(PermissionDeniedError):
            self.r.list_amendments(BLIND)
        with self.assertRaises(PermissionDeniedError):
            self.r.amendment_snapshots(
                BLIND, self.r.amendment_order[0])


class AvailableActionsTest(AmendmentTestBase):
    def test_actions_reflect_current_facts_order_independently(self):
        self.enroll("S1")
        aid = self.submit_review_adopt(
            new_version="1.1", impact={"安全规则": {"x": 1}})
        a1 = self.r.subject_available_actions(INVESTIGATOR, "S1")
        a2 = self.r.subject_available_actions(INVESTIGATOR, "S1")
        self.assertEqual(a1["blocking_reasons"], a2["blocking_reasons"])
        self.assertTrue(a1["actions"]["amendment_reconsent"]["allowed"])
        self.assertEqual(a1["actions"]["amendment_reconsent"]["amendment_id"], aid)
        self.assertFalse(a1["actions"]["perform_treatment"]["allowed"])
        # SAE/撤回始终可执行
        self.assertTrue(a1["actions"]["record_sae"]["allowed"])
        self.assertTrue(a1["actions"]["withdraw_consent"]["allowed"])
        # 完成待办后视图翻为放行
        self.r.record_consent(
            INVESTIGATOR, subject_id="S1", protocol_version="1.1",
            signed_at=self.clock.t, consent_version="ICF-2",
            document_ref="u", document_checksum="h", amendment_id=aid)
        todo = self.r.list_site_todos(INVESTIGATOR, "SITE-A")[0]
        self.r.resolve_amendment_todo(
            INVESTIGATOR, todo_id=todo["todo_id"], resolution="补充同意")
        a3 = self.r.subject_available_actions(INVESTIGATOR, "S1")
        self.assertFalse(a3["blocked"])
        self.assertTrue(a3["actions"]["perform_treatment"]["allowed"])

    def test_continue_todo_is_confirmation_only_and_does_not_block(self):
        self.enroll("S1")
        self.inject("S1")
        self.light("S1")
        self.submit_review_adopt(
            new_version="1.1", impact={"器械": {"lot": "DEV-2"}})
        actions = self.r.subject_available_actions(INVESTIGATOR, "S1")
        self.assertFalse(actions["blocked"])
        self.assertEqual(len(actions["confirmation_only_todos"]), 1)
        # 不阻断窗内访视
        act = self.r.schedule_activity(
            INVESTIGATOR, subject_id="S1", kind="影像采集",
            planned_at=self.clock.t + timedelta(days=5))
        self.assertEqual(act["status"], "已排程")
        todo = actions["confirmation_only_todos"][0]
        done = self.r.resolve_amendment_todo(
            INVESTIGATOR, todo_id=todo["todo_id"], resolution="继续")
        self.assertEqual(done["status"], "已完成")


class RetrospectionAndProvenanceTest(AmendmentTestBase):
    def test_old_version_traceable_after_new_versions_adopted(self):
        self.enroll("S1")
        self.inject("S1")
        self.light("S1")
        # 1.1 器械修订（继续）
        a1 = self.submit_review_adopt(
            new_version="1.1", impact={"器械": {"lot": "DEV-2"}})
        todo = self.todo_map()["S1"]
        self.r.resolve_amendment_todo(
            INVESTIGATOR, todo_id=todo["todo_id"], resolution="继续")
        # 1.2 安全修订（补充同意）
        a2 = self.submit_review_adopt(
            new_version="1.2", impact={"安全规则": {"rule": "加测"}})
        self.r.record_consent(
            INVESTIGATOR, subject_id="S1", protocol_version="1.2",
            signed_at=self.clock.t, consent_version="ICF-3",
            document_ref="u3", document_checksum="h3", amendment_id=a2)
        todo2 = self.todo_map()["S1"]
        self.r.resolve_amendment_todo(
            INVESTIGATOR, todo_id=todo2["todo_id"], resolution="补充同意")
        # 旧版本 1.0 的快照仍可回溯，且与当前状态无关
        snap = self.r.amendment_snapshots(DSMB, a1)
        self.assertEqual(snap[0]["facts"]["lights_completed"], ["S1-l"])
        chain = self.r.subject_provenance(INVESTIGATOR, "S1")
        trace = {a["amendment_id"]: a for a in chain["amendments"]}
        self.assertEqual(set(trace), {a1, a2})
        self.assertTrue(trace[a1]["todo"]["status"] == "已完成")
        # 修订决议进入医学决定链
        amendment_decisions = [
            d for d in chain["medical_decisions"] if d["scope"] == "amendment"]
        self.assertEqual(len(amendment_decisions), 2)
        # 受试者仍归属旧方案 1.0（治疗事实不被改写），新版本可用于新受试者
        self.assertEqual(self.r.subjects["S1"]["protocol_version"], "1.0")
        latest = self.r.latest_approved_protocol()
        self.assertEqual(latest["version"], "1.2")

    def test_exited_subject_remains_on_old_version(self):
        self.enroll("S1")
        self.inject("S1")
        aid = self.submit_review_adopt(
            new_version="1.2",
            impact={"剂量": {"cohorts": ["Q1"], "drug_dose": "6mg"}})
        todo = self.todo_map()["S1"]
        self.assertEqual(todo["required_resolution"], "退出")
        self.r.resolve_amendment_todo(
            INVESTIGATOR, todo_id=todo["todo_id"], resolution="退出",
            note="已给药，按原方案随访")
        self.assertEqual(self.r.subjects["S1"]["protocol_version"], "1.0")
        self.assertIn(aid, self.r.subjects["S1"]["amendments_exited"])
        # 退出后操作恢复（按原版本）
        act = self.r.schedule_activity(
            INVESTIGATOR, subject_id="S1", kind="激光照射",
            planned_at=self.clock.t + timedelta(hours=26),
            activity_id="S1-l")
        self.assertEqual(act["status"], "已排程")

    def test_request_order_does_not_change_snapshot_outcomes(self):
        # 先准备事实，再以不同顺序重复批准-采用两次等价场景
        def build():
            r = TrialRegistry(clock=self.clock)
            proto = r.create_protocol(INVESTIGATOR, version="1.0")
            r.submit_protocol_for_approval(INVESTIGATOR, proto["protocol_id"])
            r.approve_protocol(DSMB, proto["protocol_id"], decision="继续",
                               rationale="ok")
            r.register_site(COORDINATOR, site_id="S", name="n",
                            credentials_expire_at=self.clock.t + timedelta(days=9))
            r.review_site_credentials(COORDINATOR, "S", approved=True,
                                      qualified_versions=["1.0"], rationale="x")
            r.register_lot(COORDINATOR, lot_id="D1", kind="药物", product="p",
                           expires_at=self.clock.t + timedelta(days=9))
            r.register_lot(COORDINATOR, lot_id="V1", kind="器械", product="p",
                           expires_at=self.clock.t + timedelta(days=9))
            r.create_cohort(INVESTIGATOR, cohort_id="Q", protocol_version="1.0",
                            drug_dose="1", light_fluence="1", light_schedule="s",
                            capacity=9)
            for sid in ("X", "Y", "Z"):
                r.register_subject(INVESTIGATOR, site_id="S", subject_id=sid)
                r.record_consent(INVESTIGATOR, subject_id=sid,
                                 protocol_version="1.0", signed_at=self.clock.t,
                                 consent_version="i", document_ref="u",
                                 document_checksum="h")
                r.screen_eligibility(INVESTIGATOR, subject_id=sid,
                                     protocol_version="1.0",
                                     inclusion_met={"a": True},
                                     exclusion_met={}, decided_at=self.clock.t)
                r.enroll_subject(INVESTIGATOR, subject_id=sid,
                                 protocol_version="1.0",
                                 at=self.clock.t + timedelta(hours=1))
                r.assign_cohort(INVESTIGATOR, subject_id=sid, cohort_id="Q",
                                at=self.clock.t + timedelta(hours=2))
            return r, proto

        r1, p1 = build()
        r1.schedule_activity(INVESTIGATOR, subject_id="Y", kind="注射",
                             planned_at=self.clock.t + timedelta(hours=24),
                             activity_id="Y-i")
        r1.perform_activity(INVESTIGATOR, activity_id="Y-i",
                            at=self.clock.t + timedelta(hours=24),
                            drug_lot_id="D1")
        amd1 = r1.submit_amendment(
            INVESTIGATOR, protocol_id=p1["protocol_id"], new_version="1.1",
            impact={"剂量": {"cohorts": ["Q"]}}, rationale="r")
        r1.review_amendment(DSMB, amd1["amendment_id"], decision="批准",
                            rationale="ok")
        d1 = {row["subject_id"]: row["decision"]
              for row in r1.amendment_snapshots(DSMB, amd1["amendment_id"])}

        # 乱序：先提交修订，再推进 Y 的治疗事实，最后批准（快照以批准时刻事实为准）
        r2, p2 = build()
        amd2 = r2.submit_amendment(
            INVESTIGATOR, protocol_id=p2["protocol_id"], new_version="1.1",
            impact={"剂量": {"cohorts": ["Q"]}}, rationale="r")
        r2.schedule_activity(INVESTIGATOR, subject_id="Y", kind="注射",
                             planned_at=self.clock.t + timedelta(hours=24),
                             activity_id="Y-i")
        r2.perform_activity(INVESTIGATOR, activity_id="Y-i",
                            at=self.clock.t + timedelta(hours=24),
                            drug_lot_id="D1")
        r2.review_amendment(DSMB, amd2["amendment_id"], decision="批准",
                            rationale="ok")
        d2 = {row["subject_id"]: row["decision"]
              for row in r2.amendment_snapshots(DSMB, amd2["amendment_id"])}
        self.assertEqual(d1, d2)
        self.assertEqual(d1, {"X": "补充同意", "Y": "退出", "Z": "补充同意"})


if __name__ == "__main__":
    unittest.main()
