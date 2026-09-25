"""队列扩展期方案修订的验收测试。

验收输入覆盖：多中心不同采用顺序、紧急修订期限推进、并发确认幂等、
旧版本回溯，以及撤回/未关闭 SAE/盲态限制的优先级。
"""

import copy
import threading
import unittest
from datetime import datetime, timedelta

from trial import (
    PermissionDeniedError,
    StateConflictError,
    TrialError,
    TrialRegistry,
    ValidationError,
)

INVESTIGATOR = {"id": "doc01", "role": "研究者"}
INVESTIGATOR_B = {"id": "doc02", "role": "研究者"}
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


V2_PARAMS = {
    "observation_days": 21,
    "drug_to_light": {"min_minutes": 60, "max_minutes": 100000},
}


class AmendmentWorldTest(unittest.TestCase):
    """两个中心、四名处于不同治疗阶段的受试者。"""

    def setUp(self):
        self.clock = Clock()
        self.r = TrialRegistry(clock=self.clock)
        self._bootstrap()

    def _bootstrap(self):
        r = self.r
        self.proto = r.create_protocol(
            INVESTIGATOR, version="1.0",
            drug_to_light_min_minutes=60, drug_to_light_max_minutes=240)
        self.pid = self.proto["protocol_id"]
        r.submit_protocol_for_approval(INVESTIGATOR, self.pid)
        r.approve_protocol(DSMB, self.pid, decision="继续", rationale="v1 放行")
        for site in ("SITE-A", "SITE-B"):
            r.register_site(COORDINATOR, site_id=site, name=site,
                            credentials_expire_at=self.clock.t + timedelta(days=365))
            r.review_site_credentials(
                COORDINATOR, site, approved=True,
                qualified_versions=["1.0"], rationale="资质齐全")
        r.register_lot(COORDINATOR, lot_id="DRUG-1", kind="药物", product="光敏剂A",
                       expires_at=self.clock.t + timedelta(days=180))
        r.register_lot(COORDINATOR, lot_id="DEV-1", kind="器械", product="光纤球囊",
                       expires_at=self.clock.t + timedelta(days=180))
        r.create_cohort(INVESTIGATOR, cohort_id="C1", protocol_version="1.0",
                        drug_dose="2.0mg/kg", light_fluence="100J/cm",
                        light_schedule="单次连续", capacity=20)
        # U：已入组未治疗（A 中心）；I：已给药未照光（A 中心）；
        # L：已完成照光、观察窗已开启（B 中心）
        self.enroll_at("U", "SITE-A")
        self.enroll_at("I", "SITE-A")
        self.enroll_at("L", "SITE-B")
        self.treat_inject_only("I")
        self.treat_full("L")

    def enroll_at(self, sid, site):
        r = self.r
        actor = INVESTIGATOR_B if site == "SITE-B" else INVESTIGATOR
        r.register_subject(actor, site_id=site, subject_id=sid)
        r.record_consent(actor, subject_id=sid, protocol_version="1.0",
                         signed_at=self.clock.t, consent_version="ICF-1",
                         document_ref=f"vault://icf/{sid}",
                         document_checksum=f"sha256:{sid}")
        r.screen_eligibility(actor, subject_id=sid, protocol_version="1.0",
                             inclusion_met={"局部不可切除": True},
                             exclusion_met={}, decided_at=self.clock.t)
        r.enroll_subject(actor, subject_id=sid, protocol_version="1.0",
                         at=self.clock.t + timedelta(hours=1))
        r.assign_cohort(actor, subject_id=sid, cohort_id="C1",
                        at=self.clock.t + timedelta(hours=2))

    def treat_inject_only(self, sid):
        r = self.r
        r.schedule_activity(INVESTIGATOR, subject_id=sid, kind="注射",
                            planned_at=self.clock.t + timedelta(hours=24),
                            activity_id=f"{sid}-inj")
        r.perform_activity(INVESTIGATOR, activity_id=f"{sid}-inj",
                           at=self.clock.t + timedelta(hours=24),
                           drug_lot_id="DRUG-1")

    def treat_full(self, sid):
        r = self.r
        r.schedule_activity(INVESTIGATOR, subject_id=sid, kind="注射",
                            planned_at=self.clock.t + timedelta(hours=24),
                            activity_id=f"{sid}-inj")
        r.schedule_activity(INVESTIGATOR, subject_id=sid, kind="激光照射",
                            planned_at=self.clock.t + timedelta(hours=26),
                            activity_id=f"{sid}-light")
        r.perform_activity(INVESTIGATOR, activity_id=f"{sid}-inj",
                           at=self.clock.t + timedelta(hours=24),
                           drug_lot_id="DRUG-1")
        r.perform_activity(INVESTIGATOR, activity_id=f"{sid}-light",
                           at=self.clock.t + timedelta(hours=26),
                           device_lot_id="DEV-1")

    # ----- 构造修订的便捷方法 -----

    def submit_regular(self, *, domains=("剂量", "器械"), requires_reconsent=False,
                       new_version="2.0"):
        return self.r.submit_amendment(
            INVESTIGATOR, protocol_id=self.pid, new_version=new_version,
            summary="队列扩展：剂量与器械规则调整", impact_domains=list(domains),
            requires_reconsent=requires_reconsent)

    def approve(self, amendment, *, params=None):
        return self.r.review_amendment(
            DSMB, amendment_id=amendment["amendment_id"], approved=True,
            rationale="安全数据支持修订，放行",
            new_protocol_params=params if params is not None else V2_PARAMS)

    def row(self, amendment, sid):
        fresh = self.r.amendments[amendment["amendment_id"]]
        for row in fresh["impact_snapshot"]["subjects"]:
            if row["subject_id"] == sid:
                return row
        raise AssertionError(f"快照中缺少 {sid}")

    def fresh(self, amendment):
        return self.r.amendments[amendment["amendment_id"]]

    def adopt_both(self, amendment):
        self.r.adopt_amendment(INVESTIGATOR,
                               amendment_id=amendment["amendment_id"], site_id="SITE-A")
        self.r.adopt_amendment(INVESTIGATOR_B,
                               amendment_id=amendment["amendment_id"], site_id="SITE-B")


class SnapshotAndRecommendationTest(AmendmentWorldTest):
    def test_snapshot_must_declare_impact_domains(self):
        with self.assertRaisesRegex(ValidationError, "受影响范围"):
            self.r.submit_amendment(
                INVESTIGATOR, protocol_id=self.pid, new_version="2.0",
                summary="x", impact_domains=[], requires_reconsent=False)
        with self.assertRaisesRegex(ValidationError, "未知影响域"):
            self.submit_regular(domains=("剂量", "不存在的域"))  # type: ignore[arg-type]

    def test_snapshot_generated_only_after_dsmb_approval(self):
        amd = self.submit_regular()
        self.assertIsNone(amd["impact_snapshot"])
        with self.assertRaisesRegex(StateConflictError, "影响快照未生成"):
            self.r.impact_snapshot(DSMB, amd["amendment_id"])
        # 研究者不能自批
        with self.assertRaises(PermissionDeniedError):
            self.r.review_amendment(INVESTIGATOR, amendment_id=amd["amendment_id"],
                                    approved=True, rationale="自行放行")
        out = self.approve(amd)
        self.assertEqual(out["status"], "已批准")
        snap = self.r.impact_snapshot(DSMB, amd["amendment_id"])
        self.assertEqual({s["subject_id"] for s in snap["subjects"]}, {"U", "I", "L"})

    def test_recommendations_follow_treatment_facts(self):
        amd = self.submit_regular()
        self.approve(amd)
        self.assertEqual(self.row(amd, "U")["recommendation"], "继续")
        self.assertEqual(self.row(amd, "U")["requirements"], [])
        self.assertTrue(
            self.row(amd, "U")["treatment_facts"]["injection_completed"] is False)

        self.assertEqual(self.row(amd, "I")["recommendation"], "重新排程")
        self.assertEqual(self.row(amd, "I")["requirements"], ["重新排程"])
        facts_i = self.row(amd, "I")["treatment_facts"]
        self.assertTrue(facts_i["injection_completed"])
        self.assertFalse(facts_i["light_completed"])

        # 照光已完成：治疗事实锁定，建议继续
        self.assertEqual(self.row(amd, "L")["recommendation"], "继续")
        self.assertTrue(self.row(amd, "L")["treatment_facts"]["light_completed"])

    def test_observation_window_change_after_light_recommends_exit(self):
        amd = self.submit_regular(domains=("观察窗口",), new_version="2.0")
        self.approve(amd, params={"observation_days": 21})
        self.assertEqual(self.row(amd, "L")["recommendation"], "退出")
        # 未治疗者不受窗口规则影响，仍可继续
        self.assertEqual(self.row(amd, "U")["recommendation"], "继续")

    def test_requires_reconsent_marks_subjects(self):
        amd = self.submit_regular(requires_reconsent=True)
        self.approve(amd)
        self.assertEqual(self.row(amd, "U")["recommendation"], "补充同意")
        self.assertEqual(self.row(amd, "U")["requirements"], ["重新签署同意"])
        self.assertEqual(self.row(amd, "L")["recommendation"], "补充同意")
        # 已给药未照光者：先补同意，仍须重新排程
        row_i = self.row(amd, "I")
        self.assertEqual(row_i["recommendation"], "补充同意")
        self.assertEqual(row_i["requirements"], ["重新签署同意", "重新排程"])

    def test_snapshot_excludes_screening_and_withdrawn(self):
        self.r.register_subject(INVESTIGATOR, site_id="SITE-A", subject_id="NEW")
        self.r.withdraw_consent(INVESTIGATOR, subject_id="L",
                                at=self.clock.t + timedelta(days=2), reason="个人原因")
        amd = self.submit_regular()
        self.approve(amd)
        ids = {s["subject_id"] for s in self.fresh(amd)["impact_snapshot"]["subjects"]}
        self.assertNotIn("NEW", ids)  # 筛选中不入选
        self.assertNotIn("L", ids)    # 已撤回不入选（撤回规则优先）


class AdoptAndBlockTest(AmendmentWorldTest):
    def test_blocks_until_site_adopts_and_requirements_close(self):
        amd = self.submit_regular()
        self.approve(amd)
        # 批准后、中心采用/处置闭环前：后续操作被阻断
        with self.assertRaisesRegex(StateConflictError, "尚未闭环") as cm:
            self.r.schedule_activity(
                INVESTIGATOR, subject_id="I", kind="激光照射",
                planned_at=self.clock.t + timedelta(days=4))
        self.assertEqual(cm.exception.code, "amendment_requirements_open")
        # 未采用先处置被阻止
        with self.assertRaisesRegex(StateConflictError, "尚未采用修订") as cm2:
            self.r.resolve_subject_amendment(
                INVESTIGATOR, amendment_id=amd["amendment_id"],
                subject_id="I", decision="重新排程",
                reschedule=[{"kind": "激光照射",
                             "planned_at": self.clock.t + timedelta(days=4)}])
        self.assertEqual(cm2.exception.code, "site_amendment_not_adopted")

    def test_site_adoption_order_does_not_change_snapshot(self):
        amd = self.submit_regular()
        self.approve(amd)
        snap_before = copy.deepcopy(self.fresh(amd)["impact_snapshot"])
        # B 中心先采用、先处置，A 中心后采用
        self.r.adopt_amendment(INVESTIGATOR_B,
                               amendment_id=amd["amendment_id"], site_id="SITE-B")
        self.r.resolve_subject_amendment(
            INVESTIGATOR_B, amendment_id=amd["amendment_id"], subject_id="L",
            decision="继续")
        self.r.adopt_amendment(INVESTIGATOR,
                               amendment_id=amd["amendment_id"], site_id="SITE-A")
        self.r.resolve_subject_amendment(
            INVESTIGATOR, amendment_id=amd["amendment_id"], subject_id="U",
            decision="继续")
        # 快照是批准时刻的事实，不随后续采用顺序变化
        self.assertEqual(self.fresh(amd)["impact_snapshot"], snap_before)
        # A 中心采用即取得 2.0 资质
        self.assertIn("2.0", self.r.sites["SITE-A"]["qualified_versions"])

    def test_cannot_continue_when_reschedule_required(self):
        amd = self.submit_regular()
        self.approve(amd)
        self.adopt_both(amd)
        with self.assertRaisesRegex(StateConflictError, "必须先按新版本重新排程") as cm:
            self.r.resolve_subject_amendment(
                INVESTIGATOR, amendment_id=amd["amendment_id"],
                subject_id="I", decision="继续")
        self.assertEqual(cm.exception.code, "reschedule_required")
        # 已照光者不能重新排程（治疗事实锁定）
        with self.assertRaisesRegex(StateConflictError, "治疗事实不可改变") as cm2:
            self.r.resolve_subject_amendment(
                INVESTIGATOR_B, amendment_id=amd["amendment_id"],
                subject_id="L", decision="重新排程")
        self.assertEqual(cm2.exception.code, "treatment_fact_locked")

    def test_reschedule_flow_rebinds_and_opens_new_window(self):
        amd = self.submit_regular()
        # 新版本把给药→照光窗口放宽、观察窗改为 21 天
        self.approve(amd, params=V2_PARAMS)
        self.adopt_both(amd)
        light_at = self.clock.t + timedelta(days=4)
        out = self.r.resolve_subject_amendment(
            INVESTIGATOR, amendment_id=amd["amendment_id"], subject_id="I",
            decision="重新排程",
            reschedule=[{"kind": "激光照射", "planned_at": light_at,
                         "activity_id": "I-light2"}])
        self.assertEqual(out["status"], "已完成")
        self.assertEqual(out["final_decision"], "继续")
        # 受试者改绑新版本
        self.assertEqual(self.r.subjects["I"]["protocol_version"], "2.0")
        # 重排的照光可按新版本执行，观察窗按 21 天开启
        done = self.r.perform_activity(
            INVESTIGATOR, activity_id="I-light2", at=light_at,
            device_lot_id="DEV-1")
        self.assertEqual(done["outcome"], "按计划完成")
        window = self.r.subjects["I"]["window"]
        self.assertEqual(window["end_at"],
                         (light_at + timedelta(days=21)).isoformat(timespec="seconds"))

    def test_reconsent_flow_requires_document_before_unblock(self):
        amd = self.submit_regular(requires_reconsent=True)
        self.approve(amd)
        self.adopt_both(amd)
        # 第一次只登记决定、未交同意书：要求未闭环，仍阻断
        pending = self.r.resolve_subject_amendment(
            INVESTIGATOR, amendment_id=amd["amendment_id"], subject_id="U",
            decision="补充同意")
        self.assertEqual(pending["status"], "待完成要求")
        with self.assertRaisesRegex(StateConflictError, "尚未闭环"):
            self.r.schedule_activity(
                INVESTIGATOR, subject_id="U", kind="注射",
                planned_at=self.clock.t + timedelta(days=6))
        # 补交重新签署的同意 -> 闭环，按新版本继续
        done = self.r.resolve_subject_amendment(
            INVESTIGATOR, amendment_id=amd["amendment_id"], subject_id="U",
            decision="补充同意",
            reconsent={"signed_at": self.clock.t + timedelta(days=3),
                       "consent_version": "ICF-2",
                       "document_ref": "vault://icf/U-v2",
                       "document_checksum": "sha256:U-v2"})
        self.assertEqual(done["status"], "已完成")
        self.assertEqual(self.r.subjects["U"]["protocol_version"], "2.0")
        consent = self.r.consents[self.r.subjects["U"]["consent_id"]]
        self.assertEqual(consent["consent_version"], "ICF-2")
        self.assertEqual(consent["protocol_version"], "2.0")
        act = self.r.schedule_activity(
            INVESTIGATOR, subject_id="U", kind="注射",
            planned_at=self.clock.t + timedelta(days=6))
        self.assertEqual(act["status"], "已排程")

    def test_exit_disposition_withdraws_but_keeps_safety_records(self):
        amd = self.submit_regular(domains=("观察窗口",))
        self.approve(amd, params={"observation_days": 21})
        self.adopt_both(amd)
        self.r.resolve_subject_amendment(
            INVESTIGATOR_B, amendment_id=amd["amendment_id"], subject_id="L",
            decision="退出", note="窗口规则变化，退出随访")
        s = self.r.subjects["L"]
        self.assertTrue(s["withdrawn"])
        self.assertEqual(s["status"], "已撤回")
        with self.assertRaisesRegex(StateConflictError, "撤回") as cm:
            self.r.register_artifact(
                INVESTIGATOR_B, subject_id="L", artifact_type="影像",
                ref="vault://x", checksum="sha256:x",
                captured_at=self.clock.t + timedelta(days=6))
        self.assertEqual(cm.exception.code, "research_use_blocked")
        # 撤回后安全记录仍可登记
        sae = self.r.report_sae(
            INVESTIGATOR_B, subject_id="L", at=self.clock.t + timedelta(days=5),
            description="迟发事件", severity="轻度")
        self.assertIn(sae["sae_id"], self.r.saes)


class EmergencyAmendmentTest(AmendmentWorldTest):
    def submit_emergency(self, *, reason="出现严重器械相关信号，立即冻结",
                         hours=72, domains=("安全规则", "器械"),
                         requires_reconsent=False, new_version="2.0"):
        return self.r.submit_amendment(
            INVESTIGATOR, protocol_id=self.pid, new_version=new_version,
            summary="紧急安全修订", impact_domains=list(domains),
            requires_reconsent=requires_reconsent, emergency=True,
            reason=reason, review_deadline_hours=hours)

    def test_emergency_requires_reason_and_deadline(self):
        with self.assertRaisesRegex(ValidationError, "紧急理由"):
            self.submit_emergency(reason="")
        with self.assertRaisesRegex(ValidationError, "补审期限"):
            self.r.submit_amendment(
                INVESTIGATOR, protocol_id=self.pid, new_version="2.0",
                summary="紧急", impact_domains=["安全规则"], requires_reconsent=False,
                emergency=True, reason="x", review_deadline_hours=None)
        with self.assertRaisesRegex(ValidationError, "1~72"):
            self.submit_emergency(hours=73)

    def test_emergency_freezes_immediately_before_retro_review(self):
        amd = self.submit_emergency()
        self.assertEqual(amd["status"], "待安全委员会批准")
        self.assertIsNotNone(amd["impact_snapshot"])  # 提交即生成快照
        self.assertEqual(amd["emergency"]["review_status"], "待补审")
        # 受影响受试者立即冻结
        with self.assertRaisesRegex(StateConflictError, "紧急安全修订") as cm:
            self.r.schedule_activity(
                INVESTIGATOR, subject_id="U", kind="注射",
                planned_at=self.clock.t + timedelta(days=2))
        self.assertEqual(cm.exception.code, "emergency_amendment_freeze")
        # 冻结期中心可先采用，但补审前不得处置受试者
        self.r.adopt_amendment(INVESTIGATOR,
                               amendment_id=amd["amendment_id"], site_id="SITE-A")
        with self.assertRaisesRegex(StateConflictError, "尚待安全委员会补审") as cm2:
            self.r.resolve_subject_amendment(
                INVESTIGATOR, amendment_id=amd["amendment_id"],
                subject_id="U", decision="继续")
        self.assertEqual(cm2.exception.code, "emergency_amendment_pending_review")

    def test_deadline_advances_to_overdue_then_retro_review(self):
        amd = self.submit_emergency(hours=48)
        due_at = amd["emergency"]["review_due_at"]
        self.assertEqual(due_at, (T0 + timedelta(hours=48)).isoformat(timespec="seconds"))
        # 期限内推进不逾期
        self.clock.advance(hours=47)
        self.assertEqual(
            self.r.emergency_amendment_overdue(amd["amendment_id"])
            ["emergency"]["review_status"], "待补审")
        # 超过期限 -> 逾期
        self.clock.advance(hours=2)
        out = self.r.emergency_amendment_overdue(amd["amendment_id"])
        self.assertEqual(out["emergency"]["review_status"], "已逾期")
        # 逾期后补审仍可闭环，但保留逾期事实
        reviewed = self.r.review_amendment(
            DSMB, amendment_id=amd["amendment_id"], approved=True,
            rationale="补审认可紧急冻结", new_protocol_params=V2_PARAMS)
        self.assertEqual(reviewed["status"], "已批准")
        self.assertEqual(reviewed["emergency"]["review_status"], "已逾期")
        self.assertIsNotNone(reviewed["emergency"]["retro_review"])
        # 补审后冻结解除，中心采用后处置可进行
        self.r.adopt_amendment(INVESTIGATOR,
                               amendment_id=amd["amendment_id"], site_id="SITE-A")
        self.r.resolve_subject_amendment(
            INVESTIGATOR, amendment_id=amd["amendment_id"],
            subject_id="U", decision="继续")
        self.assertEqual(self.r.subjects["U"]["protocol_version"], "2.0")

    def test_rejected_emergency_lifts_freeze_and_cancels_dispositions(self):
        amd = self.submit_emergency()
        self.r.review_amendment(DSMB, amendment_id=amd["amendment_id"],
                                approved=False, rationale="信号不成立，解除冻结")
        self.assertEqual(self.fresh(amd)["status"], "已驳回")
        disp = self.r.subject_dispositions[(amd["amendment_id"], "U")]
        self.assertEqual(disp["status"], "已撤销")
        # 冻结解除：v1 操作恢复
        act = self.r.schedule_activity(
            INVESTIGATOR, subject_id="U", kind="注射",
            planned_at=self.clock.t + timedelta(days=2))
        self.assertEqual(act["status"], "已排程")
        # 已撤销处置不能再确认
        again = self.r.resolve_subject_amendment(
            INVESTIGATOR, amendment_id=amd["amendment_id"],
            subject_id="U", decision="继续")
        self.assertEqual(again["status"], "已撤销")

    def test_emergency_freeze_cannot_be_bypassed_by_subject_deviation(self):
        amd = self.submit_emergency()
        # 冻结期不得用受试者级紧急偏离规避修订冻结
        with self.assertRaisesRegex(StateConflictError, "紧急安全修订") as cm:
            self.r.declare_emergency_deviation(
                INVESTIGATOR, subject_id="U",
                at=self.clock.t + timedelta(hours=25),
                deviation_type="治疗前紧急处置", reason="尝试紧急照光",
                target_kind="注射",
                target_planned_at=self.clock.t + timedelta(hours=25, minutes=30))
        self.assertEqual(cm.exception.code, "emergency_amendment_freeze")


class PriorityTest(AmendmentWorldTest):
    def test_open_sae_blocks_disposition_until_dsmb_review(self):
        amd = self.submit_regular()
        self.approve(amd)
        self.adopt_both(amd)
        sae = self.r.report_sae(
            INVESTIGATOR, subject_id="I", at=self.clock.t + timedelta(days=2),
            description="严重胆管炎", severity="中度")
        with self.assertRaisesRegex(StateConflictError, "严重不良事件") as cm:
            self.r.resolve_subject_amendment(
                INVESTIGATOR, amendment_id=amd["amendment_id"],
                subject_id="I", decision="继续")
        self.assertEqual(cm.exception.code, "sae_hold")
        # SAE 复核后才能继续处置流程（仍须重新排程）
        self.r.review_sae(DSMB, sae_id=sae["sae_id"], decision="继续",
                          rationale="感染控制")
        with self.assertRaisesRegex(StateConflictError, "重新排程"):
            self.r.resolve_subject_amendment(
                INVESTIGATOR, amendment_id=amd["amendment_id"],
                subject_id="I", decision="继续")

    def test_withdrawn_subject_disposition_must_be_exit(self):
        amd = self.submit_regular()
        self.approve(amd)
        self.adopt_both(amd)
        self.r.withdraw_consent(INVESTIGATOR, subject_id="U",
                                at=self.clock.t + timedelta(days=2), reason="个人原因")
        with self.assertRaisesRegex(StateConflictError, "只能为退出") as cm:
            self.r.resolve_subject_amendment(
                INVESTIGATOR, amendment_id=amd["amendment_id"],
                subject_id="U", decision="继续")
        self.assertEqual(cm.exception.code, "subject_withdrawn")
        out = self.r.resolve_subject_amendment(
            INVESTIGATOR, amendment_id=amd["amendment_id"],
            subject_id="U", decision="退出")
        self.assertEqual(out["status"], "已完成")

    def test_blind_role_isolated_from_amendment_data(self):
        amd = self.submit_regular()
        self.approve(amd)
        with self.assertRaises(PermissionDeniedError):
            self.r.list_amendments(BLIND)
        with self.assertRaises(PermissionDeniedError):
            self.r.impact_snapshot(BLIND, amd["amendment_id"])
        with self.assertRaises(PermissionDeniedError):
            self.r.pending_todos(BLIND, site_id="SITE-A")
        # 但盲态可通过动作视图看到收窄后的阻断事实（无 blocks/治疗细节）
        view = self.r.subject_available_actions(BLIND, "I")
        self.assertTrue(view["has_open_block"])
        block = view["blocked"][0]
        self.assertEqual(block["code"], "amendment_requirements_open")
        self.assertNotIn("blocks", block)
        self.assertNotIn("schedule_treatment", view["allowed_actions"])


class TodoAndActionsTest(AmendmentWorldTest):
    def test_todos_are_site_scoped_and_close_on_confirmation(self):
        amd = self.submit_regular()
        self.approve(amd)
        todos_a = self.r.pending_todos(INVESTIGATOR, site_id="SITE-A")
        todos_b = self.r.pending_todos(INVESTIGATOR_B, site_id="SITE-B")
        subjects_a = {t["subject_id"] for t in todos_a}
        subjects_b = {t["subject_id"] for t in todos_b}
        self.assertIn(None, subjects_a)   # 中心采用待办
        self.assertEqual(subjects_a, {None, "U", "I"})
        self.assertEqual(subjects_b, {None, "L"})
        # 互不串单
        self.assertTrue(all(t["site_id"] == "SITE-A" for t in todos_a))
        self.adopt_both(amd)
        pending_adopt = [t for t in self.r.pending_todos(
            INVESTIGATOR, site_id="SITE-A", status="待处理")
            if t["kind"] == "中心采用修订"]
        self.assertEqual(pending_adopt, [])
        # 受试者处置待办在闭环后关闭
        self.r.resolve_subject_amendment(
            INVESTIGATOR, amendment_id=amd["amendment_id"], subject_id="U",
            decision="继续")
        open_u = [t for t in self.r.pending_todos(
            INVESTIGATOR, site_id="SITE-A", status="待处理")
            if t["subject_id"] == "U"]
        self.assertEqual(open_u, [])

    def test_actions_view_refreshes_through_lifecycle(self):
        amd = self.submit_regular()
        self.approve(amd)
        view = self.r.subject_available_actions(INVESTIGATOR, "I")
        self.assertTrue(view["has_open_block"])
        codes = {b["code"] for b in view["blocked"]}
        self.assertEqual(codes, {"amendment_requirements_open"})
        self.assertNotIn("schedule_treatment", view["allowed_actions"])
        self.adopt_both(amd)
        self.r.resolve_subject_amendment(
            INVESTIGATOR, amendment_id=amd["amendment_id"], subject_id="I",
            decision="重新排程",
            reschedule=[{"kind": "激光照射",
                         "planned_at": self.clock.t + timedelta(days=4),
                         "activity_id": "I-light2"}])
        view2 = self.r.subject_available_actions(INVESTIGATOR, "I")
        self.assertFalse(view2["has_open_block"])
        self.assertIn("perform_treatment", view2["allowed_actions"])


class ConcurrencyTest(AmendmentWorldTest):
    def test_concurrent_site_adoption_is_idempotent(self):
        amd = self.submit_regular()
        self.approve(amd)
        errors = []

        def adopt():
            try:
                self.r.adopt_amendment(INVESTIGATOR,
                                       amendment_id=amd["amendment_id"],
                                       site_id="SITE-A")
            except TrialError as exc:  # pragma: no cover - 并发下不应有错误
                errors.append(exc)

        threads = [threading.Thread(target=adopt) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        adoption = self.r.site_adoptions[amd["amendment_id"]]["SITE-A"]
        self.assertEqual(adoption["status"], "已采用")
        adopts = [e for e in self.r.audit_trail(target_type="site", target_id="SITE-A")
                  if e["action"] == "adopt_amendment"]
        self.assertEqual(len(adopts), 1)

    def test_concurrent_subject_resolution_confirms_once(self):
        amd = self.submit_regular()
        self.approve(amd)
        self.adopt_both(amd)
        errors = []

        def resolve():
            try:
                self.r.resolve_subject_amendment(
                    INVESTIGATOR, amendment_id=amd["amendment_id"],
                    subject_id="U", decision="继续")
            except TrialError as exc:  # pragma: no cover
                errors.append(exc)

        threads = [threading.Thread(target=resolve) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        disp = self.r.subject_dispositions[(amd["amendment_id"], "U")]
        self.assertEqual(disp["status"], "已完成")
        self.assertEqual(disp["final_decision"], "继续")
        closes = [e for e in self.r.audit_trail(target_type="subject", target_id="U")
                  if e["action"] == "resolve_subject_amendment"
                  and e["detail"].get("final_decision")]
        self.assertEqual(len(closes), 1)
        self.assertEqual(self.r.subjects["U"]["protocol_version"], "2.0")

    def test_interleaved_site_order_final_state_identical(self):
        """两个世界采用完全不同的采用/处置顺序，最终逐受试者状态必须一致。"""
        def build_and_run(order):
            clock = Clock()
            r = TrialRegistry(clock=clock)
            proto = r.create_protocol(
                INVESTIGATOR, version="1.0",
                drug_to_light_min_minutes=60, drug_to_light_max_minutes=240)
            r.submit_protocol_for_approval(INVESTIGATOR, proto["protocol_id"])
            r.approve_protocol(DSMB, proto["protocol_id"], decision="继续",
                               rationale="v1")
            for site in ("SITE-A", "SITE-B"):
                r.register_site(COORDINATOR, site_id=site, name=site,
                                credentials_expire_at=clock.t + timedelta(days=365))
                r.review_site_credentials(COORDINATOR, site, approved=True,
                                          qualified_versions=["1.0"], rationale="x")
            r.register_lot(COORDINATOR, lot_id="DRUG-1", kind="药物", product="P",
                           expires_at=clock.t + timedelta(days=180))
            r.register_lot(COORDINATOR, lot_id="DEV-1", kind="器械", product="D",
                           expires_at=clock.t + timedelta(days=180))
            r.create_cohort(INVESTIGATOR, cohort_id="C1", protocol_version="1.0",
                            drug_dose="2.0", light_fluence="100",
                            light_schedule="单次", capacity=20)
            for sid, site in (("U", "SITE-A"), ("L", "SITE-B")):
                actor = INVESTIGATOR_B if site == "SITE-B" else INVESTIGATOR
                r.register_subject(actor, site_id=site, subject_id=sid)
                r.record_consent(actor, subject_id=sid, protocol_version="1.0",
                                 signed_at=clock.t, consent_version="ICF-1",
                                 document_ref=f"vault://{sid}",
                                 document_checksum=f"sha256:{sid}")
                r.screen_eligibility(actor, subject_id=sid, protocol_version="1.0",
                                     inclusion_met={"a": True}, exclusion_met={},
                                     decided_at=clock.t)
                r.enroll_subject(actor, subject_id=sid, protocol_version="1.0",
                                 at=clock.t + timedelta(hours=1))
                r.assign_cohort(actor, subject_id=sid, cohort_id="C1",
                                at=clock.t + timedelta(hours=2))
            amd = r.submit_amendment(
                INVESTIGATOR, protocol_id=proto["protocol_id"], new_version="2.0",
                summary="修订", impact_domains=["剂量", "器械"],
                requires_reconsent=False)
            r.review_amendment(DSMB, amendment_id=amd["amendment_id"],
                               approved=True, rationale="ok",
                               new_protocol_params=V2_PARAMS)

            def do(site):
                actor = INVESTIGATOR_B if site == "SITE-B" else INVESTIGATOR
                r.adopt_amendment(actor, amendment_id=amd["amendment_id"], site_id=site)
                sid = "L" if site == "SITE-B" else "U"
                r.resolve_subject_amendment(
                    actor, amendment_id=amd["amendment_id"], subject_id=sid,
                    decision="继续")

            for site in order:
                do(site)
            return r

        r1 = build_and_run(["SITE-A", "SITE-B"])
        r2 = build_and_run(["SITE-B", "SITE-A"])
        for sid in ("U", "L"):
            self.assertEqual(r1.subjects[sid]["protocol_version"], "2.0")
            self.assertEqual(r2.subjects[sid]["protocol_version"], "2.0")
            d1 = [d for d in r1.subject_dispositions.values()
                  if d["subject_id"] == sid][0]
            d2 = [d for d in r2.subject_dispositions.values()
                  if d["subject_id"] == sid][0]
            self.assertEqual((d1["status"], d1["final_decision"]),
                             (d2["status"], d2["final_decision"]))
            # 影响快照建议在两个世界完全一致
            s1 = [a for a in r1.amendments.values()][0]["impact_snapshot"]
            s2 = [a for a in r2.amendments.values()][0]["impact_snapshot"]
            self.assertEqual(
                [(x["subject_id"], x["recommendation"], x["requirements"])
                 for x in s1["subjects"]],
                [(x["subject_id"], x["recommendation"], x["requirements"])
                 for x in s2["subjects"]])


class RetrospectiveTest(AmendmentWorldTest):
    def test_provenance_keeps_amendment_history_and_old_facts(self):
        amd = self.submit_regular()
        self.approve(amd)
        self.adopt_both(amd)
        self.r.resolve_subject_amendment(
            INVESTIGATOR_B, amendment_id=amd["amendment_id"], subject_id="L",
            decision="继续")
        chain = self.r.subject_provenance(INVESTIGATOR_B, "L")
        # 受试者已改绑新版本，但溯源链保留 v1 治疗事实与修订记录
        self.assertEqual(chain["protocol"]["version"], "2.0")
        self.assertEqual(len(chain["amendments"]), 1)
        hist = chain["amendments"][0]
        self.assertEqual(hist["base_version"], "1.0")
        self.assertEqual(hist["new_version"], "2.0")
        self.assertEqual(hist["final_decision"], "继续")
        self.assertTrue(hist["treatment_facts_at_snapshot"]["light_completed"])
        # v1 下完成的活动与批次事实未被改写
        acts = {(a["kind"], a["device_lot_id"]) for a in chain["activities"]}
        self.assertIn(("激光照射", "DEV-1"), acts)
        # 旧版本方案记录仍可回溯
        versions = {p["version"]: p["status"] for p in self.r.protocols.values()}
        self.assertEqual(versions["1.0"], "已放行")
        self.assertEqual(versions["2.0"], "已放行")
        v2 = [p for p in self.r.protocols.values() if p["version"] == "2.0"][0]
        self.assertEqual(v2["based_on"], self.pid)
        self.assertEqual(v2["introduced_by_amendment"], amd["amendment_id"])

    def test_snapshot_remains_available_after_dispositions(self):
        amd = self.submit_regular()
        self.approve(amd)
        snap_at_approval = copy.deepcopy(
            self.r.impact_snapshot(DSMB, amd["amendment_id"]))
        self.adopt_both(amd)
        self.r.resolve_subject_amendment(
            INVESTIGATOR, amendment_id=amd["amendment_id"], subject_id="U",
            decision="继续")
        self.assertEqual(self.r.impact_snapshot(DSMB, amd["amendment_id"]),
                         snap_at_approval)


if __name__ == "__main__":
    unittest.main()
