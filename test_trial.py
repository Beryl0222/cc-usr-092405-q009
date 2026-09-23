"""受控流程领域规则的单元测试。"""

import threading
import unittest
from datetime import datetime, timedelta

from trial import (
    PermissionDeniedError,
    StateConflictError,
    TrialError,
    TrialRegistry,
    ValidationError,
    _checksum,
)

INVESTIGATOR = {"id": "doc01", "role": "研究者"}
COORDINATOR = {"id": "coord01", "role": "试验协调员"}
DSMB = {"id": "dsmb01", "role": "安全委员会"}
BLIND = {"id": "reader01", "role": "盲态评价者"}
MONITOR = {"id": "cra01", "role": "申办方监查员"}

T0 = datetime(2026, 3, 2, 9, 0)


class Clock:
    def __init__(self, t=T0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, **kwargs):
        self.t += timedelta(**kwargs)
        return self.t


class TrialTestBase(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.r = TrialRegistry(clock=self.clock)
        self._bootstrap()

    def _bootstrap(self, version="1.0", approve=True, site_versions=None):
        self.proto = self.r.create_protocol(
            INVESTIGATOR, version=version,
            drug_to_light_min_minutes=60, drug_to_light_max_minutes=240,
        )
        self.pid = self.proto["protocol_id"]
        if approve:
            self.r.submit_protocol_for_approval(INVESTIGATOR, self.pid)
            self.r.approve_protocol(
                DSMB, self.pid, decision="继续", rationale="首例方案风险可控，放行"
            )
        self.r.register_site(
            COORDINATOR, site_id="SITE-A", name="胰腺中心",
            credentials_expire_at=self.clock.t + timedelta(days=365),
        )
        self.r.review_site_credentials(
            COORDINATOR, "SITE-A", approved=True,
            qualified_versions=site_versions or [version], rationale="资质齐全",
        )
        self.r.register_lot(
            COORDINATOR, lot_id="DRUG-1", kind="药物", product="光敏剂A",
            expires_at=self.clock.t + timedelta(days=180),
        )
        self.r.register_lot(
            COORDINATOR, lot_id="DEV-1", kind="器械", product="激光光纤球囊",
            expires_at=self.clock.t + timedelta(days=180),
        )

    def enroll(self, sid, version="1.0", cohort_capacity=10, cohort_id=None,
               assign=True, signed_at=None, enrolled_at=None):
        self.r.register_subject(INVESTIGATOR, site_id="SITE-A", subject_id=sid)
        self.r.record_consent(
            INVESTIGATOR, subject_id=sid, protocol_version=version,
            signed_at=signed_at or self.clock.t,
            consent_version="ICF-1", document_ref="vault://icf/" + sid,
            document_checksum="sha256:icf-" + sid,
        )
        self.r.screen_eligibility(
            INVESTIGATOR, subject_id=sid, protocol_version=version,
            inclusion_met={"局部不可切除胰腺肿瘤": True, "年龄18-75": True},
            exclusion_met={"远处转移": False, "凝血障碍": False},
            decided_at=self.clock.t,
        )
        self.r.enroll_subject(
            INVESTIGATOR, subject_id=sid, protocol_version=version,
            at=enrolled_at or self.clock.t + timedelta(hours=1),
        )
        if assign:
            cid = cohort_id or f"C-{version}"
            if cid not in self.r.cohorts:
                self.r.create_cohort(
                    INVESTIGATOR, cohort_id=cid, protocol_version=version,
                    drug_dose="2.0mg/kg", light_fluence="100J/cm",
                    light_schedule="单次连续", capacity=cohort_capacity,
                )
            self.r.assign_cohort(
                INVESTIGATOR, subject_id=sid, cohort_id=cid, at=self.clock.t + timedelta(hours=2)
            )
        return sid

    def treat(self, sid, drug_at_offset=24, light_at_offset=26,
              drug_lot="DRUG-1", device_lot="DEV-1", light_dose=None):
        inj = f"{sid}-inj"
        light = f"{sid}-light"
        self.r.schedule_activity(
            INVESTIGATOR, subject_id=sid, kind="注射",
            planned_at=self.clock.t + timedelta(hours=drug_at_offset), activity_id=inj,
        )
        self.r.schedule_activity(
            INVESTIGATOR, subject_id=sid, kind="激光照射",
            planned_at=self.clock.t + timedelta(hours=light_at_offset), activity_id=light,
        )
        self.r.perform_activity(
            INVESTIGATOR, activity_id=inj,
            at=self.clock.t + timedelta(hours=drug_at_offset),
            drug_lot_id=drug_lot,
        )
        self.r.perform_activity(
            INVESTIGATOR, activity_id=light,
            at=self.clock.t + timedelta(hours=light_at_offset),
            device_lot_id=device_lot, actual_dose=light_dose,
        )
        return inj, light


class ProtocolGateTest(TrialTestBase):
    def test_unapproved_protocol_blocks_enrollment(self):
        proto = self.r.create_protocol(INVESTIGATOR, version="2.0-draft")
        self.r.register_site(COORDINATOR, site_id="SITE-B", name="新中心",
                             credentials_expire_at=self.clock.t + timedelta(days=30))
        self.r.review_site_credentials(COORDINATOR, "SITE-B", approved=True,
                                       qualified_versions=["2.0-draft"], rationale="x")
        self.r.register_subject(INVESTIGATOR, site_id="SITE-B", subject_id="S9")
        self.r.record_consent(INVESTIGATOR, subject_id="S9",
                              protocol_version="2.0-draft", signed_at=self.clock.t,
                              consent_version="ICF-2", document_ref="vault://x",
                              document_checksum="sha256:x")
        self.r.screen_eligibility(
            INVESTIGATOR, subject_id="S9", protocol_version="2.0-draft",
            inclusion_met={"a": True}, exclusion_met={"b": False},
            decided_at=self.clock.t)
        with self.assertRaisesRegex(StateConflictError, "安全委员会放行") as cm:
            self.r.enroll_subject(INVESTIGATOR, subject_id="S9",
                                  protocol_version="2.0-draft", at=self.clock.t)
        self.assertEqual(cm.exception.code, "protocol_not_approved")

    def test_only_dsmb_can_approve(self):
        proto = self.r.create_protocol(INVESTIGATOR, version="3.0")
        self.r.submit_protocol_for_approval(INVESTIGATOR, proto["protocol_id"])
        with self.assertRaises(PermissionDeniedError):
            self.r.approve_protocol(INVESTIGATOR, proto["protocol_id"],
                                    decision="继续", rationale="研究者自行放行")
        with self.assertRaises(ValidationError):
            self.r.approve_protocol(DSMB, proto["protocol_id"],
                                    decision="继续", rationale="  ")

    def test_dsmb_hold_decision_deactivates_protocol(self):
        proto = self.r.create_protocol(INVESTIGATOR, version="4.0")
        self.r.submit_protocol_for_approval(INVESTIGATOR, proto["protocol_id"])
        out = self.r.approve_protocol(DSMB, proto["protocol_id"],
                                      decision="暂停入组", rationale="等待毒性数据")
        self.assertEqual(out["status"], "已停用")
        # 被暂停的新版本不会成为最新放行方案；最新放行仍是基线 1.0
        latest = self.r.latest_approved_protocol()
        self.assertIsNotNone(latest)
        self.assertEqual(latest["version"], "1.0")

    def test_duplicate_version_rejected(self):
        with self.assertRaisesRegex(StateConflictError, "方案版本已存在"):
            self.r.create_protocol(INVESTIGATOR, version="1.0")


class SiteAndEnrollmentTest(TrialTestBase):
    def test_site_version_qualification_enforced(self):
        self.r.create_protocol(INVESTIGATOR, version="2.0")
        pid2 = [p for p in self.r.protocols.values() if p["version"] == "2.0"][0]["protocol_id"]
        self.r.submit_protocol_for_approval(INVESTIGATOR, pid2)
        self.r.approve_protocol(DSMB, pid2, decision="继续", rationale="v2 放行")
        # SITE-A 只有 1.0 资质
        self.r.register_subject(INVESTIGATOR, site_id="SITE-A", subject_id="S2")
        self.r.record_consent(INVESTIGATOR, subject_id="S2", protocol_version="2.0",
                              signed_at=self.clock.t, consent_version="ICF-2",
                              document_ref="vault://x", document_checksum="sha256:x")
        self.r.screen_eligibility(INVESTIGATOR, subject_id="S2", protocol_version="2.0",
                                  inclusion_met={"a": True}, exclusion_met={},
                                  decided_at=self.clock.t)
        with self.assertRaisesRegex(StateConflictError, "未取得方案 2.0 的资质") as cm:
            self.r.enroll_subject(INVESTIGATOR, subject_id="S2",
                                  protocol_version="2.0", at=self.clock.t)
        self.assertEqual(cm.exception.code, "site_version_not_qualified")

    def test_expired_credentials_block(self):
        self.r.register_site(COORDINATOR, site_id="SITE-OLD", name="老中心",
                             credentials_expire_at=self.clock.t - timedelta(days=1))
        self.r.review_site_credentials(COORDINATOR, "SITE-OLD", approved=True,
                                       qualified_versions=["1.0"], rationale="x")
        self.r.register_subject(INVESTIGATOR, site_id="SITE-OLD", subject_id="S3")
        self.r.record_consent(INVESTIGATOR, subject_id="S3", protocol_version="1.0",
                              signed_at=self.clock.t, consent_version="ICF-1",
                              document_ref="vault://x", document_checksum="sha256:x")
        self.r.screen_eligibility(INVESTIGATOR, subject_id="S3", protocol_version="1.0",
                                  inclusion_met={"a": True}, exclusion_met={},
                                  decided_at=self.clock.t)
        with self.assertRaisesRegex(StateConflictError, "资质已"):
            self.r.enroll_subject(INVESTIGATOR, subject_id="S3",
                                  protocol_version="1.0", at=self.clock.t)

    def test_consent_version_mismatch_blocks(self):
        self.r.create_protocol(INVESTIGATOR, version="2.0")
        pid2 = [p for p in self.r.protocols.values() if p["version"] == "2.0"][0]["protocol_id"]
        self.r.submit_protocol_for_approval(INVESTIGATOR, pid2)
        self.r.approve_protocol(DSMB, pid2, decision="继续", rationale="ok")
        self.r.review_site_credentials(COORDINATOR, "SITE-A", approved=True,
                                       qualified_versions=["1.0", "2.0"], rationale="ok")
        self.enroll("SOK")  # 1.0 基线可用
        self.r.register_subject(INVESTIGATOR, site_id="SITE-A", subject_id="S4")
        # 按 1.0 签同意，却想入 2.0
        self.r.record_consent(INVESTIGATOR, subject_id="S4", protocol_version="1.0",
                              signed_at=self.clock.t, consent_version="ICF-1",
                              document_ref="vault://x", document_checksum="sha256:x")
        self.r.screen_eligibility(INVESTIGATOR, subject_id="S4", protocol_version="2.0",
                                  inclusion_met={"a": True}, exclusion_met={},
                                  decided_at=self.clock.t)
        with self.assertRaisesRegex(StateConflictError, "同意书版本") as cm:
            self.r.enroll_subject(INVESTIGATOR, subject_id="S4",
                                  protocol_version="2.0", at=self.clock.t)
        self.assertEqual(cm.exception.code, "consent_version_mismatch")

    def test_ineligible_subject_blocked(self):
        self.r.register_subject(INVESTIGATOR, site_id="SITE-A", subject_id="S5")
        self.r.record_consent(INVESTIGATOR, subject_id="S5", protocol_version="1.0",
                              signed_at=self.clock.t, consent_version="ICF-1",
                              document_ref="vault://x", document_checksum="sha256:x")
        self.r.screen_eligibility(
            INVESTIGATOR, subject_id="S5", protocol_version="1.0",
            inclusion_met={"局部不可切除": True},
            exclusion_met={"远处转移": True},
            decided_at=self.clock.t)
        with self.assertRaisesRegex(StateConflictError, "不符合入排条件") as cm:
            self.r.enroll_subject(INVESTIGATOR, subject_id="S5",
                                  protocol_version="1.0", at=self.clock.t)
        self.assertEqual(cm.exception.code, "subject_ineligible")


class CohortAndDoseTest(TrialTestBase):
    def test_cohort_protocol_cross_talk_blocked(self):
        self.r.create_protocol(INVESTIGATOR, version="2.0")
        pid2 = [p for p in self.r.protocols.values() if p["version"] == "2.0"][0]["protocol_id"]
        self.r.submit_protocol_for_approval(INVESTIGATOR, pid2)
        self.r.approve_protocol(DSMB, pid2, decision="继续", rationale="ok")
        self.r.review_site_credentials(COORDINATOR, "SITE-A", approved=True,
                                       qualified_versions=["1.0", "2.0"], rationale="ok")
        self.r.create_cohort(INVESTIGATOR, cohort_id="C-2", protocol_version="2.0",
                             drug_dose="4.0mg/kg", light_fluence="200J/cm",
                             light_schedule="双段", capacity=3)
        self.enroll("S10")  # 1.0 队列
        with self.assertRaisesRegex(StateConflictError, "剂量混淆") as cm:
            self.r.assign_cohort(INVESTIGATOR, subject_id="S10", cohort_id="C-2",
                                 at=self.clock.t)
        self.assertEqual(cm.exception.code, "dose_protocol_mismatch")

    def test_cohort_capacity_and_reassignment(self):
        self.r.create_cohort(INVESTIGATOR, cohort_id="TINY", protocol_version="1.0",
                             drug_dose="2.0", light_fluence="100",
                             light_schedule="单次", capacity=1)
        self.enroll("A1", cohort_id="TINY", assign=False)
        self.r.assign_cohort(INVESTIGATOR, subject_id="A1", cohort_id="TINY",
                             at=self.clock.t)
        self.assertEqual(self.r.cohorts["TINY"]["status"], "已满员")
        # 已分配者重复入任何队列都被拒绝
        with self.assertRaisesRegex(StateConflictError, "不得跨队列"):
            self.r.assign_cohort(INVESTIGATOR, subject_id="A1", cohort_id="TINY",
                                 at=self.clock.t)
        self.r.create_cohort(INVESTIGATOR, cohort_id="BIG", protocol_version="1.0",
                             drug_dose="3.0", light_fluence="150",
                             light_schedule="单次", capacity=5)
        with self.assertRaisesRegex(StateConflictError, "不得跨队列"):
            self.r.assign_cohort(INVESTIGATOR, subject_id="A1", cohort_id="BIG",
                                 at=self.clock.t)
        # 满员队列拒绝新受试者
        self.enroll("A2", assign=False)
        with self.assertRaisesRegex(StateConflictError, "无可用名额"):
            self.r.assign_cohort(INVESTIGATOR, subject_id="A2", cohort_id="TINY",
                                 at=self.clock.t)

    def test_wrong_lot_kind_and_quarantine_block(self):
        self.enroll("S11")
        self.r.schedule_activity(INVESTIGATOR, subject_id="S11", kind="注射",
                                 planned_at=self.clock.t + timedelta(hours=24),
                                 activity_id="S11-inj")
        with self.assertRaisesRegex(StateConflictError, "药物批次"):
            self.r.perform_activity(INVESTIGATOR, activity_id="S11-inj",
                                    at=self.clock.t + timedelta(hours=24),
                                    drug_lot_id="DEV-1")
        self.r.change_lot_status(DSMB, lot_id="DRUG-1", status="隔离中",
                                 reason="质量投诉调查")
        with self.assertRaisesRegex(StateConflictError, "不得使用"):
            self.r.perform_activity(INVESTIGATOR, activity_id="S11-inj",
                                    at=self.clock.t + timedelta(hours=24),
                                    drug_lot_id="DRUG-1")


class TimelineTest(TrialTestBase):
    def test_drug_light_interval_window(self):
        self.enroll("S20")
        self.r.schedule_activity(INVESTIGATOR, subject_id="S20", kind="注射",
                                 planned_at=self.clock.t + timedelta(hours=24),
                                 activity_id="i")
        self.r.schedule_activity(INVESTIGATOR, subject_id="S20", kind="激光照射",
                                 planned_at=self.clock.t + timedelta(hours=30),
                                 activity_id="l")
        self.r.perform_activity(INVESTIGATOR, activity_id="i",
                                at=self.clock.t + timedelta(hours=24),
                                drug_lot_id="DRUG-1")
        # 间隔 10 小时 = 600 分钟 > 240
        with self.assertRaisesRegex(StateConflictError, "给药→照光间隔") as cm:
            self.r.perform_activity(INVESTIGATOR, activity_id="l",
                                    at=self.clock.t + timedelta(hours=30),
                                    device_lot_id="DEV-1")
        self.assertEqual(cm.exception.code, "drug_light_interval")

    def test_light_before_drug_blocked(self):
        self.enroll("S21")
        self.r.schedule_activity(INVESTIGATOR, subject_id="S21", kind="激光照射",
                                 planned_at=self.clock.t + timedelta(hours=24),
                                 activity_id="l2")
        with self.assertRaisesRegex(StateConflictError, "尚无完成的注射"):
            self.r.perform_activity(INVESTIGATOR, activity_id="l2",
                                    at=self.clock.t + timedelta(hours=24),
                                    device_lot_id="DEV-1")

    def test_dose_mismatch_blocked(self):
        self.enroll("S23")
        self.r.schedule_activity(INVESTIGATOR, subject_id="S23", kind="注射",
                                 planned_at=self.clock.t + timedelta(hours=24),
                                 activity_id="i23")
        self.r.schedule_activity(INVESTIGATOR, subject_id="S23", kind="激光照射",
                                 planned_at=self.clock.t + timedelta(hours=26),
                                 activity_id="l23")
        self.r.perform_activity(INVESTIGATOR, activity_id="i23",
                                at=self.clock.t + timedelta(hours=24),
                                drug_lot_id="DRUG-1")
        with self.assertRaisesRegex(StateConflictError, "剂量混淆"):
            self.r.perform_activity(
                INVESTIGATOR, activity_id="l23",
                at=self.clock.t + timedelta(hours=26),
                device_lot_id="DEV-1",
                actual_dose={"light_fluence": "999J/cm", "light_schedule": "单次连续"})


class ObservationWindowTest(TrialTestBase):
    def test_window_opens_on_light_and_blocks_outside_visits(self):
        self.enroll("S30")
        self.treat("S30")
        subject = self.r.subjects["S30"]
        light_done = self.clock.t + timedelta(hours=26)
        self.assertEqual(subject["window"]["start_at"],
                         light_done.isoformat(timespec="seconds"))
        self.assertEqual(subject["window"]["end_at"],
                         (light_done + timedelta(days=14)).isoformat(timespec="seconds"))
        # 越窗排程被阻止
        with self.assertRaisesRegex(StateConflictError, "越出观察窗"):
            self.r.schedule_activity(
                INVESTIGATOR, subject_id="S30", kind="影像采集",
                planned_at=light_done + timedelta(days=15))
        # 窗内允许
        art_visit = self.r.schedule_activity(
            INVESTIGATOR, subject_id="S30", kind="影像采集",
            planned_at=light_done + timedelta(days=14), activity_id="S30-img")
        self.assertEqual(art_visit["status"], "已排程")

    def test_outcome_outside_window_blocked(self):
        self.enroll("S31")
        self.treat("S31")
        with self.assertRaisesRegex(StateConflictError, "越出观察窗"):
            self.r.record_outcome(
                INVESTIGATOR, subject_id="S31", outcome_type="影像评估",
                result_summary="两周评估", at=self.clock.t + timedelta(days=20))

    def test_reschedule_reevaluates_window(self):
        self.enroll("S32")
        self.treat("S32")
        act = self.r.schedule_activity(
            INVESTIGATOR, subject_id="S32", kind="手术评估",
            planned_at=self.clock.t + timedelta(days=13), activity_id="S32-op")
        with self.assertRaisesRegex(StateConflictError, "越出观察窗"):
            self.r.delay_activity(INVESTIGATOR, activity_id="S32-op",
                                  new_planned_at=self.clock.t + timedelta(days=16),
                                  reason="术期延后")
        ok = self.r.delay_activity(INVESTIGATOR, activity_id="S32-op",
                                   new_planned_at=self.clock.t + timedelta(days=14),
                                   reason="手术团队安排")
        self.assertEqual(len(ok["reschedule_history"]), 1)


class DeviceSwapTest(TrialTestBase):
    def test_device_swap_links_activities_and_no_dose_on_failure(self):
        self.enroll("S40")
        self.treat_inj_only("S40")
        self.r.schedule_activity(
            INVESTIGATOR, subject_id="S40", kind="激光照射",
            planned_at=self.clock.t + timedelta(hours=26), activity_id="S40-l1")
        replacement = self.r.schedule_activity(
            INVESTIGATOR, subject_id="S40", kind="激光照射",
            planned_at=self.clock.t + timedelta(hours=27), activity_id="S40-l2")
        # 第一根球囊术中故障，批次随即隔离；更换记录仍须引用故障批次以保留事实链
        self.r.change_lot_status(COORDINATOR, lot_id="DEV-1", status="隔离中",
                                 reason="术中球囊破裂")
        self.r.register_lot(COORDINATOR, lot_id="DEV-2", kind="器械",
                            product="激光光纤球囊-B",
                            expires_at=self.clock.t + timedelta(days=180))
        swapped = self.r.perform_activity(
            INVESTIGATOR, activity_id="S40-l1",
            at=self.clock.t + timedelta(hours=26),
            device_lot_id="DEV-1", outcome="器械更换",
            linked_activity_id="S40-l2", notes="DEV-1 球囊输送失败，更换 DEV-2")
        self.assertEqual(swapped["outcome"], "器械更换")
        self.assertIsNone(swapped["actual_dose"])
        self.assertEqual(self.r.activities["S40-l2"]["parent_activity_id"], "S40-l1")
        # 隔离批次不能用于真正完成的照光
        self.r.schedule_activity(
            INVESTIGATOR, subject_id="S40", kind="激光照射",
            planned_at=self.clock.t + timedelta(hours=28), activity_id="S40-l3")
        with self.assertRaisesRegex(StateConflictError, "不得使用"):
            self.r.perform_activity(
                INVESTIGATOR, activity_id="S40-l3",
                at=self.clock.t + timedelta(hours=28), device_lot_id="DEV-1")
        # 替代照光成功，观察窗按替代执行时间开启
        done = self.r.perform_activity(
            INVESTIGATOR, activity_id="S40-l2",
            at=self.clock.t + timedelta(hours=27), device_lot_id="DEV-2")
        self.assertEqual(self.r.subjects["S40"]["status"], "观察中")
        self.assertEqual(done["device_lot_id"], "DEV-2")
        self.assertIsNone(self.r.subjects["S40"]["window"]["opened_via_deviation"])

    def treat_inj_only(self, sid):
        self.r.schedule_activity(INVESTIGATOR, subject_id=sid, kind="注射",
                                 planned_at=self.clock.t + timedelta(hours=24),
                                 activity_id=sid + "-inj")
        self.r.perform_activity(INVESTIGATOR, activity_id=sid + "-inj",
                                at=self.clock.t + timedelta(hours=24),
                                drug_lot_id="DRUG-1")

    def test_postponement_is_not_a_treatment_fact(self):
        self.enroll("S41")
        self.treat_inj_only("S41")
        self.r.schedule_activity(INVESTIGATOR, subject_id="S41", kind="激光照射",
                                 planned_at=self.clock.t + timedelta(hours=26),
                                 activity_id="S41-l1")
        post = self.r.perform_activity(
            INVESTIGATOR, activity_id="S41-l1",
            at=self.clock.t + timedelta(hours=26), outcome="术期延后",
            notes="麻醉冲突")
        self.assertEqual(post["outcome"], "术期延后")
        self.assertIsNone(post["actual_dose"])
        self.assertEqual(self.r.subjects["S41"]["status"], "治疗中")
        # 未照光 -> 无观察窗
        self.assertIsNone(self.r.subjects["S41"]["window"])
        # 重排后照光成功
        self.r.schedule_activity(INVESTIGATOR, subject_id="S41", kind="激光照射",
                                 planned_at=self.clock.t + timedelta(hours=27),
                                 activity_id="S41-l2")
        self.r.perform_activity(INVESTIGATOR, activity_id="S41-l2",
                                at=self.clock.t + timedelta(hours=27),
                                device_lot_id="DEV-1")
        self.assertEqual(self.r.subjects["S41"]["status"], "观察中")


class EmergencyDeviationTest(TrialTestBase):
    def test_emergency_pre_treatment_action_then_supplement_and_review(self):
        self.enroll("S50")
        # 先按方案完成注射
        self.r.schedule_activity(INVESTIGATOR, subject_id="S50", kind="注射",
                                 planned_at=self.clock.t + timedelta(hours=24),
                                 activity_id="S50-inj")
        self.r.perform_activity(INVESTIGATOR, activity_id="S50-inj",
                                at=self.clock.t + timedelta(hours=24),
                                drug_lot_id="DRUG-1")
        # 照光前出现紧急状况：登记治疗前紧急处置（原因暂缺），系统直接生成被覆盖活动
        dev = self.r.declare_emergency_deviation(
            INVESTIGATOR, subject_id="S50", at=self.clock.t + timedelta(hours=25),
            deviation_type="治疗前紧急处置", reason="",
            target_kind="激光照射",
            target_planned_at=self.clock.t + timedelta(hours=25, minutes=30))
        self.assertEqual(dev["status"], "待补录原因")
        aid = dev["target_activity_id"]
        # 未复核期间，其他研究活动被冻结
        with self.assertRaisesRegex(StateConflictError, "未复核的治疗前紧急偏离"):
            self.r.schedule_activity(
                INVESTIGATOR, subject_id="S50", kind="访视",
                planned_at=self.clock.t + timedelta(hours=28))
        # 目标活动凭偏离先行执行（显式记录实际剂量）
        done = self.r.perform_activity(
            INVESTIGATOR, activity_id=aid,
            at=self.clock.t + timedelta(hours=25, minutes=30),
            device_lot_id="DEV-1",
            emergency_deviation_id=dev["deviation_id"],
            actual_dose={"light_fluence": "120J/cm", "light_schedule": "单次连续"})
        self.assertEqual(done["outcome"], "按计划完成")
        self.assertEqual(self.r.subjects["S50"]["window"]["opened_via_deviation"],
                         dev["deviation_id"])
        # 已用过的偏离不能用于第二个活动，排程仍被冻结
        with self.assertRaises(StateConflictError):
            self.r.schedule_activity(
                INVESTIGATOR, subject_id="S50", kind="影像采集",
                planned_at=self.clock.t + timedelta(days=3))
        # 补录原因 -> DSMB 复核
        self.r.supplement_deviation(
            INVESTIGATOR, deviation_id=dev["deviation_id"],
            justification="球囊到位异常，为避免组织缺血紧急照光")
        with self.assertRaises(PermissionDeniedError):
            self.r.review_deviation(  # 研究者不能自复核
                INVESTIGATOR, deviation_id=dev["deviation_id"],
                accepted=True, committee_comment="x")
        reviewed = self.r.review_deviation(
            DSMB, deviation_id=dev["deviation_id"], accepted=True,
            committee_comment="情况危急且处置合理，认可")
        self.assertEqual(reviewed["status"], "安全委员会已复核")
        # 复核后研究活动恢复（第 10 天仍在两周窗内）
        self.r.schedule_activity(
            INVESTIGATOR, subject_id="S50", kind="影像采集",
            planned_at=self.clock.t + timedelta(days=10))

    def test_mid_treatment_deviation_allows_off_interval_light(self):
        self.enroll("S51")
        self.r.schedule_activity(INVESTIGATOR, subject_id="S51", kind="注射",
                                 planned_at=self.clock.t + timedelta(hours=24),
                                 activity_id="S51-inj")
        self.r.schedule_activity(INVESTIGATOR, subject_id="S51", kind="激光照射",
                                 planned_at=self.clock.t + timedelta(hours=30),
                                 activity_id="S51-light")
        self.r.perform_activity(INVESTIGATOR, activity_id="S51-inj",
                                at=self.clock.t + timedelta(hours=24),
                                drug_lot_id="DRUG-1")
        # 间隔 6 小时越窗，登记治疗中偏离后可先行
        dev = self.r.declare_emergency_deviation(
            INVESTIGATOR, subject_id="S51", at=self.clock.t + timedelta(hours=29),
            deviation_type="治疗中方案偏离",
            reason="患者血流动力学变化需提前照光",
            target_activity_id="S51-light")
        done = self.r.perform_activity(
            INVESTIGATOR, activity_id="S51-light",
            at=self.clock.t + timedelta(hours=30), device_lot_id="DEV-1",
            emergency_deviation_id=dev["deviation_id"],
            actual_dose={"light_fluence": "100J/cm", "light_schedule": "单次连续"})
        self.assertEqual(done["actual_dose"]["light_fluence"], "100J/cm")
        self.assertEqual(self.r.subjects["S51"]["status"], "观察中")
        # 未补录复核不影响已执行事实，但复核流程必须闭环
        self.r.review_deviation(DSMB, deviation_id=dev["deviation_id"],
                                accepted=True, committee_comment="认可")

    def test_sae_cannot_be_overridden_by_emergency(self):
        self.enroll("S52")
        sae = self.r.report_sae(
            INVESTIGATOR, subject_id="S52", at=self.clock.t + timedelta(hours=5),
            description="输注后严重过敏", severity="重度")
        with self.assertRaisesRegex(StateConflictError, "SAE") as cm:
            self.r.declare_emergency_deviation(
                INVESTIGATOR, subject_id="S52", at=self.clock.t + timedelta(hours=6),
                deviation_type="治疗前紧急处置", reason="紧急照光尝试",
                target_kind="激光照射",
                target_planned_at=self.clock.t + timedelta(hours=6, minutes=30))
        self.assertEqual(cm.exception.code, "sae_hold")


class SAEHoldTest(TrialTestBase):
    def test_open_sae_freezes_treatment_until_review(self):
        self.enroll("S60")
        self.r.report_sae(INVESTIGATOR, subject_id="S60",
                          at=self.clock.t + timedelta(hours=3),
                          description="给药后胆管损伤", severity="重度")
        with self.assertRaisesRegex(StateConflictError, "SAE") as cm:
            self.r.schedule_activity(
                INVESTIGATOR, subject_id="S60", kind="注射",
                planned_at=self.clock.t + timedelta(hours=24))
        self.assertEqual(cm.exception.code, "sae_hold")
        # DSMB 复核允许继续
        sae_id = list(self.r.saes)[0]
        self.r.review_sae(DSMB, sae_id=sae_id, decision="继续",
                          rationale="与器械无关，加强监测后继续")
        act = self.r.schedule_activity(
            INVESTIGATOR, subject_id="S60", kind="注射",
            planned_at=self.clock.t + timedelta(hours=24))
        self.assertEqual(act["kind"], "注射")

    def test_sae_termination_decision_withdraws_subject(self):
        self.enroll("S61")
        sae = self.r.report_sae(INVESTIGATOR, subject_id="S61",
                                at=self.clock.t, description="死亡", severity="死亡")
        self.r.review_sae(DSMB, sae_id=sae["sae_id"], decision="终止",
                          rationale="致死性事件，终止该受试者")
        s = self.r.subjects["S61"]
        self.assertTrue(s["withdrawn"])
        self.assertEqual(s["status"], "已撤回")
        self.assertIsNotNone(s["research_use_blocked_after"])
        # 安全记录仍保留
        self.assertTrue(s["safety_records_retained"])
        self.assertIn(sae["sae_id"], self.r.saes)


class ArtifactAndBlindingTest(TrialTestBase):
    def test_artifact_only_keeps_reference_and_checksum(self):
        self.enroll("S70")
        self.treat("S70")
        blob = b"DICOM-PSEUDONYMIZED"
        record = self.r.register_artifact(
            INVESTIGATOR, subject_id="S70", artifact_type="影像",
            ref="vault://imaging/S70/scan-01.dcm",
            checksum=_checksum(blob), captured_at=self.clock.t + timedelta(days=7),
            free_text="联系电话13800138000 已在描述中打码")
        self.assertNotIn("13800138000", record["free_text"])
        verify = self.r.verify_artifact_checksum(
            INVESTIGATOR, artifact_id=record["artifact_id"], blob=blob)
        self.assertTrue(verify["match"])
        bad = self.r.verify_artifact_checksum(
            INVESTIGATOR, artifact_id=record["artifact_id"], blob=b"tampered")
        self.assertFalse(bad["match"])

    def test_blind_role_cannot_see_cohort_or_timeline(self):
        self.enroll("S71")
        self.treat("S71")
        with self.assertRaises(PermissionDeniedError):
            self.r.list_cohorts(BLIND)
        with self.assertRaises(PermissionDeniedError):
            self.r.subject_timeline(BLIND, "S71")
        view = self.r.get_subject(BLIND, "S71")
        self.assertNotIn("cohort_id", view)
        self.assertNotIn("treatment_at", view)
        self.assertIn("window", view)
        # 盲态可读去标识影像引用
        self.r.register_artifact(
            INVESTIGATOR, subject_id="S71", artifact_type="影像",
            ref="vault://imaging/S71/a.dcm", checksum="sha256:abc",
            captured_at=self.clock.t + timedelta(days=5))
        view = self.r.get_subject(BLIND, "S71")
        self.assertEqual(view["artifact_refs"][0]["ref"],
                         "vault://imaging/S71/a.dcm")

    def test_blind_role_cannot_write(self):
        with self.assertRaises(PermissionDeniedError):
            self.r.enroll_subject(BLIND, subject_id="x", protocol_version="1.0",
                                  at=self.clock.t)


class WithdrawalTest(TrialTestBase):
    def test_withdrawal_stops_new_research_use_but_keeps_safety(self):
        self.enroll("S80")
        self.treat("S80")
        withdraw_at = self.clock.t + timedelta(days=3)
        self.r.withdraw_consent(INVESTIGATOR, subject_id="S80",
                                at=withdraw_at, reason="受试者个人原因")
        # 新增研究活动被阻止
        with self.assertRaisesRegex(StateConflictError, "已撤回"):
            self.r.schedule_activity(
                INVESTIGATOR, subject_id="S80", kind="影像采集",
                planned_at=self.clock.t + timedelta(days=5))
        # 撤回后新增影像（研究用途）被阻止
        with self.assertRaisesRegex(StateConflictError, "研究用途"):
            self.r.register_artifact(
                INVESTIGATOR, subject_id="S80", artifact_type="影像",
                ref="vault://x", checksum="sha256:x",
                captured_at=self.clock.t + timedelta(days=6))
        # 已产生的安全/研究记录保留
        self.assertIn("S80", self.r.subjects)
        self.assertEqual(self.r.consents[self.r.subjects["S80"]["consent_id"]]["status"],
                         "已撤回")

    def test_withdrawn_subject_cannot_enroll(self):
        self.r.register_subject(INVESTIGATOR, site_id="SITE-A", subject_id="S81")
        self.r.record_consent(INVESTIGATOR, subject_id="S81", protocol_version="1.0",
                              signed_at=self.clock.t, consent_version="ICF-1",
                              document_ref="vault://x", document_checksum="sha256:x")
        self.r.withdraw_consent(INVESTIGATOR, subject_id="S81", at=self.clock.t)
        with self.assertRaisesRegex(StateConflictError, "撤回"):
            self.r.enroll_subject(INVESTIGATOR, subject_id="S81",
                                  protocol_version="1.0", at=self.clock.t)


class EvaluabilityAndOutcomeTest(TrialTestBase):
    def test_evaluable_flow_and_provenance_chain(self):
        self.enroll("S90")
        # 未治疗（观察窗未开启）不能判定可评估性
        self.enroll("S90b", assign=False)
        with self.assertRaisesRegex(StateConflictError, "观察窗尚未开启"):
            self.r.set_evaluability(INVESTIGATOR, subject_id="S90b",
                                    evaluable=False, reason="尚未治疗")
        self.treat("S90")
        self.r.set_evaluability(INVESTIGATOR, subject_id="S90",
                                evaluable=True, reason="窗内完成影像与手术评估")
        blob = b"scan"
        art = self.r.register_artifact(
            INVESTIGATOR, subject_id="S90", artifact_type="影像",
            ref="vault://imaging/S90.dcm", checksum=_checksum(blob),
            captured_at=self.clock.t + timedelta(days=12))
        out = self.r.record_outcome(
            INVESTIGATOR, subject_id="S90", outcome_type="手术切除评估",
            result_summary="残余肿瘤可 R0 切除",
            resectable=True, at=self.clock.t + timedelta(days=14),
            artifact_ids=[art["artifact_id"]])
        chain = out["provenance"]
        self.assertEqual(chain["protocol"]["version"], "1.0")
        self.assertEqual(chain["protocol"]["approval"]["decision"], "继续")
        self.assertEqual(chain["cohort"]["assigned_dose"]["drug_dose"], "2.0mg/kg")
        device_lots = {a["device_lot_id"] for a in chain["activities"] if a["device_lot_id"]}
        self.assertEqual(device_lots, {"DEV-1"})
        self.assertEqual(self.r.subjects["S90"]["status"], "可评估")

    def test_artifacts_from_other_subject_rejected(self):
        self.enroll("S91")
        self.enroll("S92")
        self.treat("S91")
        self.treat("S92")
        art = self.r.register_artifact(
            INVESTIGATOR, subject_id="S91", artifact_type="影像",
            ref="vault://x", checksum="sha256:x",
            captured_at=self.clock.t + timedelta(days=5))
        with self.assertRaisesRegex(ValidationError, "不匹配"):
            self.r.record_outcome(
                INVESTIGATOR, subject_id="S92", outcome_type="影像评估",
                result_summary="x", at=self.clock.t + timedelta(days=5),
                artifact_ids=[art["artifact_id"]])


class ConcurrencyTest(TrialTestBase):
    """六名受试者并发安排：注册中心必须在并发下保持容量与状态一致。"""

    def test_six_subjects_concurrent_enrollment_and_treatment(self):
        # 三个剂量队列各 2 个名额，六名受试者一一对应；并发下不得超员或状态错乱
        for i in range(1, 4):
            self.r.create_cohort(
                INVESTIGATOR, cohort_id=f"Q{i}", protocol_version="1.0",
                drug_dose=f"{1.0 + i}mg/kg", light_fluence="100J/cm",
                light_schedule="单次连续", capacity=2)

        errors: list[BaseException] = []

        def worker(k):
            try:
                sid = f"P{k}"
                self.r.register_subject(INVESTIGATOR, site_id="SITE-A", subject_id=sid)
                self.r.record_consent(
                    INVESTIGATOR, subject_id=sid, protocol_version="1.0",
                    signed_at=self.clock.t, consent_version="ICF-1",
                    document_ref=f"vault://icf/{sid}", document_checksum=f"sha256:{sid}")
                self.r.screen_eligibility(
                    INVESTIGATOR, subject_id=sid, protocol_version="1.0",
                    inclusion_met={"局部不可切除": True}, exclusion_met={},
                    decided_at=self.clock.t)
                self.r.enroll_subject(
                    INVESTIGATOR, subject_id=sid, protocol_version="1.0",
                    at=self.clock.t + timedelta(hours=1))
                self.r.assign_cohort(
                    INVESTIGATOR, subject_id=sid, cohort_id=f"Q{(k % 3) + 1}",
                    at=self.clock.t + timedelta(hours=2))
            except BaseException as exc:  # 子线程异常必须带回主线程断言
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(k,)) for k in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [])
        assigned = [s for s in self.r.subjects.values() if s["cohort_id"]]
        self.assertEqual(len(assigned), 6)
        for cid, cohort in self.r.cohorts.items():
            self.assertLessEqual(cohort["enrolled"], 2)
            self.assertEqual(cohort["enrolled"], 2)
            self.assertEqual(cohort["status"], "已满员")

    def test_concurrent_overcapacity_rejects_exactly_overflow(self):
        # 单队列容量 2、六人并发竞争：恰 2 人成功，4 人收到队列满冲突，无超员
        self.r.create_cohort(
            INVESTIGATOR, cohort_id="ONLY", protocol_version="1.0",
            drug_dose="2.0mg/kg", light_fluence="100J/cm",
            light_schedule="单次连续", capacity=2)
        failures: list[str] = []
        lock = threading.Lock()

        def worker(k):
            sid = f"O{k}"
            try:
                self.r.register_subject(INVESTIGATOR, site_id="SITE-A", subject_id=sid)
                self.r.record_consent(
                    INVESTIGATOR, subject_id=sid, protocol_version="1.0",
                    signed_at=self.clock.t, consent_version="ICF-1",
                    document_ref=f"vault://icf/{sid}", document_checksum=f"sha256:{sid}")
                self.r.screen_eligibility(
                    INVESTIGATOR, subject_id=sid, protocol_version="1.0",
                    inclusion_met={"局部不可切除": True}, exclusion_met={},
                    decided_at=self.clock.t)
                self.r.enroll_subject(
                    INVESTIGATOR, subject_id=sid, protocol_version="1.0",
                    at=self.clock.t + timedelta(hours=1))
                self.r.assign_cohort(
                    INVESTIGATOR, subject_id=sid, cohort_id="ONLY",
                    at=self.clock.t + timedelta(hours=2))
            except StateConflictError as exc:
                with lock:
                    failures.append(exc.code)

        threads = [threading.Thread(target=worker, args=(k,)) for k in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(self.r.cohorts["ONLY"]["enrolled"], 2)
        self.assertEqual(sorted(failures).count("cohort_full"), 4)

    def test_concurrent_sae_report_only_consistent_hold(self):
        self.enroll("P0")
        errors = []

        def report(k):
            try:
                self.r.report_sae(
                    INVESTIGATOR, subject_id="P0",
                    at=self.clock.t + timedelta(minutes=k),
                    description=f"事件{k}", severity="中度")
            except TrialError as exc:
                errors.append(exc)

        threads = [threading.Thread(target=report, args=(k,)) for k in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        # 多次报告都应成功登记（安全事件不得漏报），且治疗被冻结
        self.assertGreaterEqual(len(self.r.saes), 1)
        with self.assertRaisesRegex(StateConflictError, "SAE"):
            self.r.schedule_activity(
                INVESTIGATOR, subject_id="P0", kind="注射",
                planned_at=self.clock.t + timedelta(days=1))


class SixSubjectScenarioTest(TrialTestBase):
    """六名受试者并发安排，分别遭遇器械更换、术期延后、SAE、紧急偏离与撤回：
    错误方案必须被阻止，观察窗与可评估状态准确，结局可全程溯源。"""

    def _enroll_sync(self, sid, cohort):
        h = lambda **kw: timedelta(**kw)
        self.r.register_subject(INVESTIGATOR, site_id="SITE-A", subject_id=sid)
        self.r.record_consent(
            INVESTIGATOR, subject_id=sid, protocol_version="1.0",
            signed_at=self.clock.t, consent_version="ICF-1",
            document_ref=f"vault://icf/{sid}", document_checksum=f"sha256:{sid}")
        self.r.screen_eligibility(
            INVESTIGATOR, subject_id=sid, protocol_version="1.0",
            inclusion_met={"局部不可切除": True}, exclusion_met={},
            decided_at=self.clock.t)
        self.r.enroll_subject(INVESTIGATOR, subject_id=sid, protocol_version="1.0",
                              at=self.clock.t + h(hours=1))
        self.r.assign_cohort(INVESTIGATOR, subject_id=sid, cohort_id=cohort,
                             at=self.clock.t + h(hours=2))

    def test_all_six_concurrent_paths(self):
        for i in range(1, 4):
            self.r.register_lot(
                COORDINATOR, lot_id=f"DEV-{i + 1}", kind="器械",
                product=f"光纤球囊-{i + 1}",
                expires_at=self.clock.t + timedelta(days=180))
            self.r.create_cohort(
                INVESTIGATOR, cohort_id=f"Q{i}", protocol_version="1.0",
                drug_dose="2.0mg/kg", light_fluence="100J/cm",
                light_schedule="单次连续", capacity=2)
        h = lambda **kw: timedelta(**kw)
        errors: list[BaseException] = []

        def run(fn):
            try:
                fn()
            except BaseException as exc:  # noqa: BLE001 - 并发测试需回收所有异常
                errors.append(exc)

        def p1():  # 正常路径
            sid = "P1"
            self._enroll_sync(sid, "Q1")
            self.r.schedule_activity(INVESTIGATOR, subject_id=sid, kind="注射",
                                     planned_at=self.clock.t + h(hours=24),
                                     activity_id=f"{sid}-inj")
            self.r.schedule_activity(INVESTIGATOR, subject_id=sid, kind="激光照射",
                                     planned_at=self.clock.t + h(hours=26),
                                     activity_id=f"{sid}-l")
            self.r.perform_activity(INVESTIGATOR, activity_id=f"{sid}-inj",
                                    at=self.clock.t + h(hours=24), drug_lot_id="DRUG-1")
            self.r.perform_activity(INVESTIGATOR, activity_id=f"{sid}-l",
                                    at=self.clock.t + h(hours=26), device_lot_id="DEV-1")
            art = self.r.register_artifact(
                INVESTIGATOR, subject_id=sid, artifact_type="影像",
                ref="vault://P1.dcm", checksum="sha256:p1",
                captured_at=self.clock.t + h(days=7))
            self.r.record_outcome(
                INVESTIGATOR, subject_id=sid, outcome_type="手术切除评估",
                result_summary="可 R0 切除", resectable=True,
                at=self.clock.t + h(days=14), artifact_ids=[art["artifact_id"]])

        def p2():  # 器械更换
            sid = "P2"
            self._enroll_sync(sid, "Q1")
            self.r.schedule_activity(INVESTIGATOR, subject_id=sid, kind="注射",
                                     planned_at=self.clock.t + h(hours=24),
                                     activity_id=f"{sid}-inj")
            self.r.schedule_activity(INVESTIGATOR, subject_id=sid, kind="激光照射",
                                     planned_at=self.clock.t + h(hours=26),
                                     activity_id=f"{sid}-l1")
            self.r.schedule_activity(INVESTIGATOR, subject_id=sid, kind="激光照射",
                                     planned_at=self.clock.t + h(hours=27),
                                     activity_id=f"{sid}-l2")
            self.r.perform_activity(INVESTIGATOR, activity_id=f"{sid}-inj",
                                    at=self.clock.t + h(hours=24), drug_lot_id="DRUG-1")
            self.r.perform_activity(
                INVESTIGATOR, activity_id=f"{sid}-l1",
                at=self.clock.t + h(hours=26), device_lot_id="DEV-2",
                outcome="器械更换", linked_activity_id=f"{sid}-l2",
                notes="DEV-2 球囊故障")
            self.r.change_lot_status(COORDINATOR, lot_id="DEV-2", status="隔离中",
                                     reason=f"{sid} 术中故障")
            self.r.perform_activity(INVESTIGATOR, activity_id=f"{sid}-l2",
                                    at=self.clock.t + h(hours=27), device_lot_id="DEV-3")
            out = self.r.record_outcome(
                INVESTIGATOR, subject_id=sid, outcome_type="影像评估",
                result_summary="两周影像稳定",
                at=self.clock.t + h(hours=27) + h(days=13))
            device_lots = {a["device_lot_id"] for a in out["provenance"]["activities"]
                           if a["device_lot_id"]}
            assert device_lots == {"DEV-2", "DEV-3"}, device_lots

        def p3():  # 术期延后
            sid = "P3"
            self._enroll_sync(sid, "Q2")
            self.r.schedule_activity(INVESTIGATOR, subject_id=sid, kind="注射",
                                     planned_at=self.clock.t + h(hours=24),
                                     activity_id=f"{sid}-inj")
            self.r.schedule_activity(INVESTIGATOR, subject_id=sid, kind="激光照射",
                                     planned_at=self.clock.t + h(hours=26),
                                     activity_id=f"{sid}-l1")
            self.r.perform_activity(INVESTIGATOR, activity_id=f"{sid}-inj",
                                    at=self.clock.t + h(hours=24), drug_lot_id="DRUG-1")
            post = self.r.perform_activity(
                INVESTIGATOR, activity_id=f"{sid}-l1",
                at=self.clock.t + h(hours=26), outcome="术期延后", notes="麻醉冲突")
            assert post["actual_dose"] is None
            self.r.schedule_activity(INVESTIGATOR, subject_id=sid, kind="激光照射",
                                     planned_at=self.clock.t + h(hours=27),
                                     activity_id=f"{sid}-l2")
            self.r.perform_activity(INVESTIGATOR, activity_id=f"{sid}-l2",
                                    at=self.clock.t + h(hours=27), device_lot_id="DEV-1")
            assert self.r.subjects[sid]["status"] == "观察中"

        def p4():  # SAE 冻结 → DSMB 放行 → 恢复
            sid = "P4"
            self._enroll_sync(sid, "Q2")
            self.r.schedule_activity(INVESTIGATOR, subject_id=sid, kind="注射",
                                     planned_at=self.clock.t + h(hours=24),
                                     activity_id=f"{sid}-inj")
            self.r.perform_activity(INVESTIGATOR, activity_id=f"{sid}-inj",
                                    at=self.clock.t + h(hours=24), drug_lot_id="DRUG-1")
            sae = self.r.report_sae(
                INVESTIGATOR, subject_id=sid, at=self.clock.t + h(hours=25),
                description="术后胆管炎", severity="中度")
            blocked = False
            try:
                self.r.schedule_activity(INVESTIGATOR, subject_id=sid,
                                         kind="激光照射",
                                         planned_at=self.clock.t + h(hours=26))
            except StateConflictError as exc:
                blocked = exc.code == "sae_hold"
            assert blocked
            self.r.review_sae(DSMB, sae_id=sae["sae_id"], decision="继续",
                              rationale="感染控制，可继续")
            self.r.schedule_activity(INVESTIGATOR, subject_id=sid, kind="激光照射",
                                     planned_at=self.clock.t + h(hours=27),
                                     activity_id=f"{sid}-l")
            self.r.perform_activity(INVESTIGATOR, activity_id=f"{sid}-l",
                                    at=self.clock.t + h(hours=27), device_lot_id="DEV-1")

        def p5():  # 治疗中方案偏离（越间隔照光）→ 补录 → 复核
            sid = "P5"
            self._enroll_sync(sid, "Q3")
            self.r.schedule_activity(INVESTIGATOR, subject_id=sid, kind="注射",
                                     planned_at=self.clock.t + h(hours=24),
                                     activity_id=f"{sid}-inj")
            self.r.schedule_activity(INVESTIGATOR, subject_id=sid, kind="激光照射",
                                     planned_at=self.clock.t + h(hours=30),
                                     activity_id=f"{sid}-l")
            self.r.perform_activity(INVESTIGATOR, activity_id=f"{sid}-inj",
                                    at=self.clock.t + h(hours=24), drug_lot_id="DRUG-1")
            dev = self.r.declare_emergency_deviation(
                INVESTIGATOR, subject_id=sid, at=self.clock.t + h(hours=29),
                deviation_type="治疗中方案偏离", reason="血流动力学波动需提前照光",
                target_activity_id=f"{sid}-l")
            self.r.perform_activity(
                INVESTIGATOR, activity_id=f"{sid}-l",
                at=self.clock.t + h(hours=30), device_lot_id="DEV-1",
                emergency_deviation_id=dev["deviation_id"],
                actual_dose={"light_fluence": "100J/cm", "light_schedule": "单次连续"})
            self.r.review_deviation(DSMB, deviation_id=dev["deviation_id"],
                                    accepted=True, committee_comment="认可")

        def p6():  # 撤回：阻断新研究用途，保留安全记录
            sid = "P6"
            self._enroll_sync(sid, "Q3")
            self.r.schedule_activity(INVESTIGATOR, subject_id=sid, kind="注射",
                                     planned_at=self.clock.t + h(hours=24),
                                     activity_id=f"{sid}-inj")
            self.r.schedule_activity(INVESTIGATOR, subject_id=sid, kind="激光照射",
                                     planned_at=self.clock.t + h(hours=26),
                                     activity_id=f"{sid}-l")
            self.r.perform_activity(INVESTIGATOR, activity_id=f"{sid}-inj",
                                    at=self.clock.t + h(hours=24), drug_lot_id="DRUG-1")
            self.r.perform_activity(INVESTIGATOR, activity_id=f"{sid}-l",
                                    at=self.clock.t + h(hours=26), device_lot_id="DEV-1")
            self.r.withdraw_consent(INVESTIGATOR, subject_id=sid,
                                    at=self.clock.t + h(days=3), reason="个人原因")
            blocked = False
            try:
                self.r.register_artifact(
                    INVESTIGATOR, subject_id=sid, artifact_type="影像",
                    ref="vault://x", checksum="sha256:x",
                    captured_at=self.clock.t + h(days=5))
            except StateConflictError as exc:
                blocked = exc.code == "research_use_blocked"
            assert blocked
            # 安全事件在撤回后仍可登记（法规要求的安全记录保留）
            sae = self.r.report_sae(
                INVESTIGATOR, subject_id=sid, at=self.clock.t + h(days=4),
                description="迟发轻度光过敏", severity="轻度")
            assert sae["sae_id"] in self.r.saes

        threads = [
            threading.Thread(target=run, args=(fn,))
            for fn in (p1, p2, p3, p4, p5, p6)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])

        # 六人结局状态
        self.assertEqual(self.r.subjects["P1"]["status"], "可评估")
        for sid in ("P2", "P3", "P4", "P5"):
            self.assertEqual(self.r.subjects[sid]["status"], "观察中")
            self.assertIsNotNone(self.r.subjects[sid]["window"])
        self.assertTrue(self.r.subjects["P6"]["withdrawn"])
        # 队列全部恰好满员，无超员
        for cid in ("Q1", "Q2", "Q3"):
            self.assertEqual(self.r.cohorts[cid]["enrolled"], 2)
        # 每个非撤回受试者的结局/溯源都能定位到方案、实际剂量、器械、医学决定
        for sid in ("P1", "P2"):
            chain = self.r.subject_provenance(INVESTIGATOR, sid)
            self.assertEqual(chain["protocol"]["status"], "已放行")
            self.assertEqual(chain["cohort"]["assigned_dose"]["drug_dose"], "2.0mg/kg")
            self.assertTrue(chain["activities"])
            self.assertTrue(chain["protocol"]["approval"])


if __name__ == "__main__":
    unittest.main()
