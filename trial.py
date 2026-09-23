"""光动力早期试验的受控流程领域模块。

覆盖范围：方案版本与安全委员会（DSMB）放行、中心资质、受试者同意与入排、
药物/器械批次、剂量队列、操作时间线、紧急偏离与严重不良事件（SAE）、
去标识化影像/病理引用、盲态隔离、受试者撤回，以及观察窗、可评估状态与全程溯源。

本模块只做状态机与规则校验，不涉及持久化与网络；所有写入方法均为线程安全，
返回的是记录快照（深拷贝），调用方不能绕过注册中心修改记录。
"""

from __future__ import annotations

import copy
import csv
import hashlib
import io
import re
import threading
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from typing import Any, Callable, Optional

# ---------------------------------------------------------------------------
# 常量与枚举（受控词表，禁止调用方自由拼写）
# ---------------------------------------------------------------------------

ROLES = ("研究者", "试验协调员", "安全委员会", "盲态评价者", "申办方监查员")

PROTOCOL_STATUSES = ("草拟", "待安全委员会放行", "已放行", "已停用")
SITE_STATUSES = ("待资质审核", "已批准", "已暂停", "已终止")
SUBJECT_STATUSES = (
    "筛选中",
    "已入组",
    "治疗中",
    "观察中",
    "可评估",
    "已撤回",
)
CONSENT_STATUSES = ("已签署", "已撤回")
COHORT_STATUSES = ("招募中", "已满员", "已关闭")
LOT_STATUSES = ("合格", "隔离中", "已耗尽", "已召回")
VISIT_KINDS = ("注射", "激光照射", "手术评估", "影像采集", "病理采集", "访视")
OUTCOME_TYPES = ("影像评估", "病理评估", "手术切除评估")
SAE_STATUSES = ("待报告", "已报告", "安全委员会已复核", "已关闭")
DEVIATION_STATUSES = ("待补录原因", "待复核", "安全委员会已复核")
DECISION_STATUSES = ("继续", "暂停入组", "终止")
ACTIVITY_OUTCOMES = ("按计划完成", "器械更换", "术期延后", "取消")

# 治疗前的方案/批次/设备阻断适用于这些活动
TREATMENT_ACTIVITIES = ("注射", "激光照射")
# 产生治疗事实的活动：记录实际剂量
DOSE_BEARING_ACTIVITIES = ("注射",)
# 给药→照光的允许间隔（药物代谢窗口），按方案参数 drug_to_light_min/max 校验
# 安全观察窗默认 14 天（两周后评估残余肿瘤可否切除）
DEFAULT_OBSERVATION_DAYS = 14
DEFAULT_RESECT_DAYS = 14

# 盲态评价者可见的受试者字段
BLIND_SAFE_SUBJECT_FIELDS = (
    "subject_id",
    "site_id",
    "protocol_version",
    "status",
    "withdrawn",
    "window",
    "evaluable",
)


class TrialError(Exception):
    """所有领域规则冲突的基类，code 为稳定的机器可读错误码。"""

    code = "trial_error"

    def __init__(self, message: str, *, code: Optional[str] = None):
        super().__init__(message)
        if code:
            self.code = code


class NotFoundError(TrialError):
    code = "not_found"


class StateConflictError(TrialError):
    code = "state_conflict"


class PermissionDeniedError(TrialError):
    code = "permission_denied"


class ValidationError(TrialError):
    code = "validation_error"


# ---------------------------------------------------------------------------
# 内部工具
# ---------------------------------------------------------------------------

def _parse_dt(value: Any) -> datetime:
    """接受 datetime 或 ISO 字符串，统一转成 naive datetime（秒精度比较）。"""
    if isinstance(value, datetime):
        return value.replace(microsecond=0)
    if isinstance(value, str):
        text = value.strip().replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            raise ValidationError(f"无法解析时间：{value!r}")
        if parsed.tzinfo is not None:
            parsed = parsed.replace(tzinfo=None)
        return parsed.replace(microsecond=0)
    if isinstance(value, date):
        return datetime(value.year, value.month, value.day)
    raise ValidationError(f"时间类型不支持：{type(value).__name__}")


def _new_id(prefix: str) -> str:
    # 进程内唯一即可；测试需要确定性时可由调用方显式传入 *_id
    import uuid

    return f"{prefix}_{uuid.uuid4().hex[:10]}"


def _redact_pii_text(text: str) -> str:
    """自由文本去标识：身份证/护照号、电话、邮箱等直接模式先打码。"""
    if not isinstance(text, str):
        return text
    patterns = (
        (r"[\w.+-]+@[\w-]+\.[\w.-]+", "[邮箱]"),
        (r"(?<!\d)1[3-9]\d{9}(?!\d)", "[电话]"),
        (r"(?<!\d)\d{17}[\dXx](?!\d)", "[证件号]"),
    )
    out = text
    for pattern, repl in patterns:
        out = re.sub(pattern, repl, out)
    return out


def _checksum(blob: bytes) -> str:
    return "sha256:" + hashlib.sha256(blob).hexdigest()


# ---------------------------------------------------------------------------
# 溯源事件
# ---------------------------------------------------------------------------

@dataclass
class AuditEvent:
    seq: int
    at: str
    actor_id: str
    actor_role: str
    action: str
    target_type: str
    target_id: str
    detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "at": self.at,
            "actor_id": self.actor_id,
            "actor_role": self.actor_role,
            "action": self.action,
            "target_type": self.target_type,
            "target_id": self.target_id,
            "detail": copy.deepcopy(self.detail),
        }


# ---------------------------------------------------------------------------
# 注册中心
# ---------------------------------------------------------------------------

class TrialRegistry:
    """线程安全的试验受控流程注册中心（内存实现，接口即业务契约）。"""

    def __init__(self, *, clock: Optional[Callable[[], datetime]] = None):
        self._lock = threading.RLock()
        self._clock = clock or (lambda: datetime.now())
        self._seq = 0
        self._audit: list[AuditEvent] = []

        self.protocols: dict[str, dict[str, Any]] = {}
        self.protocol_order: list[str] = []
        self.sites: dict[str, dict[str, Any]] = {}
        self.subjects: dict[str, dict[str, Any]] = {}
        self.cohorts: dict[str, dict[str, Any]] = {}
        self.lots: dict[str, dict[str, Any]] = {}
        self.consents: dict[str, dict[str, Any]] = {}
        self.eligibility: dict[str, dict[str, Any]] = {}
        self.assignments: dict[str, dict[str, Any]] = {}
        self.activities: dict[str, dict[str, Any]] = {}
        self.deviations: dict[str, dict[str, Any]] = {}
        self.saes: dict[str, dict[str, Any]] = {}
        self.artifacts: dict[str, dict[str, Any]] = {}
        self.outcomes: dict[str, dict[str, Any]] = {}
        self.decisions: list[dict[str, Any]] = []

    # ----- 基础工具 ------------------------------------------------------

    def _now(self) -> datetime:
        return self._clock().replace(microsecond=0)

    def _audit_log(
        self,
        actor: dict[str, Any],
        action: str,
        target_type: str,
        target_id: str,
        detail: Optional[dict[str, Any]] = None,
    ) -> AuditEvent:
        self._seq += 1
        event = AuditEvent(
            seq=self._seq,
            at=self._now().isoformat(timespec="seconds"),
            actor_id=actor["id"],
            actor_role=actor["role"],
            action=action,
            target_type=target_type,
            target_id=target_id,
            detail=detail or {},
        )
        self._audit.append(event)
        return event

    def audit_trail(self, *, target_type: Optional[str] = None,
                    target_id: Optional[str] = None) -> list[dict[str, Any]]:
        """审计追踪：可按实体过滤；任何角色都可读取自己权限内的溯源记录。"""
        with self._lock:
            out = []
            for event in self._audit:
                if target_type and event.target_type != target_type:
                    continue
                if target_id and event.target_id != target_id:
                    continue
                out.append(event.to_dict())
            return out

    @staticmethod
    def _require_role(actor: dict[str, Any], *roles: str) -> None:
        if actor.get("role") not in roles:
            raise PermissionDeniedError(
                f"角色 {actor.get('role')!r} 无权执行该操作，允许：{ '、'.join(roles) }"
            )

    @staticmethod
    def _actor(actor: dict[str, Any]) -> dict[str, str]:
        if not isinstance(actor, dict) or not actor.get("id") or not actor.get("role"):
            raise ValidationError("操作者必须包含 id 与 role")
        if actor["role"] not in ROLES:
            raise ValidationError(f"未知角色：{actor['role']}")
        return {"id": str(actor["id"]), "role": actor["role"]}

    def _get(self, store: dict[str, Any], kind: str, key: str) -> dict[str, Any]:
        record = store.get(key)
        if record is None:
            raise NotFoundError(f"{kind}不存在：{key}")
        return record

    @staticmethod
    def _snapshot(record: dict[str, Any]) -> dict[str, Any]:
        return copy.deepcopy(record)

    # ----- 方案版本 ------------------------------------------------------

    def create_protocol(
        self,
        actor: dict[str, Any],
        *,
        version: str,
        based_on: Optional[str] = None,
        observation_days: int = DEFAULT_OBSERVATION_DAYS,
        resect_assessment_days: int = DEFAULT_RESECT_DAYS,
        drug_to_light_min_minutes: int = 60,
        drug_to_light_max_minutes: int = 240,
        notes: str = "",
        protocol_id: Optional[str] = None,
    ) -> dict[str, Any]:
        actor = self._actor(actor)
        self._require_role(actor, "研究者", "试验协调员")
        version = str(version).strip()
        if not re.fullmatch(r"[A-Za-z0-9._-]+", version):
            raise ValidationError("方案版本号只允许字母数字及 . _ -")
        for proto in self.protocols.values():
            if proto["version"] == version:
                raise StateConflictError(f"方案版本已存在：{version}", code="duplicate_protocol")
        if based_on is not None and based_on not in self.protocols:
            raise NotFoundError(f"基线方案不存在：{based_on}")
        pid = protocol_id or _new_id("proto")
        record = {
            "protocol_id": pid,
            "version": version,
            "based_on": based_on,
            "status": "草拟",
            "observation_days": int(observation_days),
            "resect_assessment_days": int(resect_assessment_days),
            "drug_to_light": {
                "min_minutes": int(drug_to_light_min_minutes),
                "max_minutes": int(drug_to_light_max_minutes),
            },
            "notes": notes,
            "approval": None,
            "created_at": self._now().isoformat(timespec="seconds"),
        }
        with self._lock:
            self.protocols[pid] = record
            self.protocol_order.append(pid)
            self._audit_log(actor, "create_protocol", "protocol", pid,
                            {"version": version, "based_on": based_on})
            return self._snapshot(record)

    def submit_protocol_for_approval(self, actor: dict[str, Any], protocol_id: str) -> dict[str, Any]:
        actor = self._actor(actor)
        self._require_role(actor, "研究者", "试验协调员")
        with self._lock:
            record = self._get(self.protocols, "方案", protocol_id)
            if record["status"] != "草拟":
                raise StateConflictError(
                    f"方案状态为 {record['status']}，仅草拟方案可提交放行"
                )
            record["status"] = "待安全委员会放行"
            self._audit_log(actor, "submit_protocol", "protocol", protocol_id)
            return self._snapshot(record)

    def approve_protocol(
        self,
        actor: dict[str, Any],
        protocol_id: str,
        *,
        decision: str,
        rationale: str,
    ) -> dict[str, Any]:
        """安全委员会放行决议。decision 为 继续/暂停入组/终止；仅“继续”等于放行。"""
        actor = self._actor(actor)
        self._require_role(actor, "安全委员会")
        if decision not in DECISION_STATUSES:
            raise ValidationError(f"决议必须是：{'、'.join(DECISION_STATUSES)}")
        if not str(rationale).strip():
            raise ValidationError("放行决议必须写明理由")
        with self._lock:
            record = self._get(self.protocols, "方案", protocol_id)
            if record["status"] != "待安全委员会放行":
                raise StateConflictError(
                    f"方案状态为 {record['status']}，安全委员会只能复核待放行方案"
                )
            at = self._now().isoformat(timespec="seconds")
            approval = {
                "decision": decision,
                "rationale": rationale,
                "committee_actor_id": actor["id"],
                "at": at,
            }
            record["approval"] = approval
            record["status"] = "已放行" if decision == "继续" else "已停用"
            self.decisions.append(
                {"scope": "protocol", "target_id": protocol_id, **approval}
            )
            self._audit_log(actor, "approve_protocol", "protocol", protocol_id, approval)
            return self._snapshot(record)

    def latest_approved_protocol(self) -> Optional[dict[str, Any]]:
        with self._lock:
            for pid in reversed(self.protocol_order):
                proto = self.protocols[pid]
                if proto["status"] == "已放行":
                    return self._snapshot(proto)
            return None

    def retire_protocol(self, actor: dict[str, Any], protocol_id: str, *, reason: str) -> dict[str, Any]:
        actor = self._actor(actor)
        self._require_role(actor, "安全委员会", "试验协调员")
        with self._lock:
            record = self._get(self.protocols, "方案", protocol_id)
            if record["status"] == "已停用":
                raise StateConflictError("方案已停用")
            record["status"] = "已停用"
            record["retired_reason"] = reason
            record["retired_at"] = self._now().isoformat(timespec="seconds")
            self._audit_log(actor, "retire_protocol", "protocol", protocol_id,
                            {"reason": reason})
            return self._snapshot(record)

    def _approved(self, protocol_id: str) -> dict[str, Any]:
        proto = self._get(self.protocols, "方案", protocol_id)
        if proto["status"] != "已放行" or not proto.get("approval"):
            raise StateConflictError(
                f"方案 {proto['version']} 尚未获得安全委员会放行，不得用于研究活动",
                code="protocol_not_approved",
            )
        return proto

    # ----- 中心资质 ------------------------------------------------------

    def register_site(
        self,
        actor: dict[str, Any],
        *,
        site_id: str,
        name: str,
        qualified_versions: Optional[list[str]] = None,
        credentials_expire_at: Any,
    ) -> dict[str, Any]:
        actor = self._actor(actor)
        self._require_role(actor, "试验协调员")
        if site_id in self.sites:
            raise StateConflictError(f"中心已存在：{site_id}", code="duplicate_site")
        expire = _parse_dt(credentials_expire_at)
        record = {
            "site_id": site_id,
            "name": name,
            "status": "待资质审核",
            "qualified_versions": list(qualified_versions or []),
            "credentials_expire_at": expire.isoformat(timespec="seconds"),
            "credential_review": None,
        }
        with self._lock:
            self.sites[site_id] = record
            self._audit_log(actor, "register_site", "site", site_id)
            return self._snapshot(record)

    def review_site_credentials(
        self,
        actor: dict[str, Any],
        site_id: str,
        *,
        approved: bool,
        qualified_versions: list[str],
        rationale: str,
    ) -> dict[str, Any]:
        actor = self._actor(actor)
        self._require_role(actor, "试验协调员", "安全委员会")
        with self._lock:
            record = self._get(self.sites, "中心", site_id)
            versions = []
            for version in qualified_versions:
                proto = self._find_protocol_by_version(version)
                versions.append(proto["version"])
            review = {
                "approved": bool(approved),
                "qualified_versions": versions,
                "rationale": rationale,
                "reviewed_by": actor["id"],
                "at": self._now().isoformat(timespec="seconds"),
            }
            record["credential_review"] = review
            record["qualified_versions"] = versions
            record["status"] = "已批准" if approved else "已暂停"
            self._audit_log(actor, "review_site", "site", site_id, review)
            return self._snapshot(record)

    def change_site_status(
        self, actor: dict[str, Any], site_id: str, *, status: str, reason: str
    ) -> dict[str, Any]:
        actor = self._actor(actor)
        self._require_role(actor, "试验协调员", "安全委员会")
        if status not in SITE_STATUSES:
            raise ValidationError(f"中心状态必须是：{'、'.join(SITE_STATUSES)}")
        with self._lock:
            record = self._get(self.sites, "中心", site_id)
            record["status"] = status
            self._audit_log(actor, "change_site_status", "site", site_id,
                            {"status": status, "reason": reason})
            return self._snapshot(record)

    def _find_protocol_by_version(self, version: str) -> dict[str, Any]:
        for proto in self.protocols.values():
            if proto["version"] == version:
                return proto
        raise NotFoundError(f"方案版本不存在：{version}")

    def _site_can_run(self, site_id: str, protocol_id: str) -> dict[str, Any]:
        site = self._get(self.sites, "中心", site_id)
        proto = self._get(self.protocols, "方案", protocol_id)
        if site["status"] != "已批准":
            raise StateConflictError(
                f"中心 {site_id} 状态为 {site['status']}，不得开展研究活动",
                code="site_not_qualified",
            )
        if proto["version"] not in site["qualified_versions"]:
            raise StateConflictError(
                f"中心 {site_id} 未取得方案 {proto['version']} 的资质授权",
                code="site_version_not_qualified",
            )
        expire = _parse_dt(site["credentials_expire_at"])
        if expire < self._now():
            raise StateConflictError(
                f"中心 {site_id} 资质已于 {site['credentials_expire_at']} 到期",
                code="site_credentials_expired",
            )
        return site

    # ----- 受试者、同意与入排 -------------------------------------------

    def register_subject(
        self, actor: dict[str, Any], *, site_id: str, subject_id: Optional[str] = None
    ) -> dict[str, Any]:
        actor = self._actor(actor)
        self._require_role(actor, "研究者", "试验协调员")
        sid = subject_id or _new_id("subj")
        with self._lock:
            if sid in self.subjects:
                raise StateConflictError(f"受试者已存在：{sid}", code="duplicate_subject")
            self._get(self.sites, "中心", site_id)
            record = {
                "subject_id": sid,
                "site_id": site_id,
                "status": "筛选中",
                "protocol_version": None,
                "protocol_id": None,
                "cohort_id": None,
                "consent_id": None,
                "enrolled_at": None,
                "treatment_at": None,
                "window": None,
                "evaluable": None,
                "evaluable_reason": None,
                "withdrawn": False,
                "withdrawn_at": None,
                "research_use_blocked_after": None,
                "safety_records_retained": True,
            }
            self.subjects[sid] = record
            self._audit_log(actor, "register_subject", "subject", sid,
                            {"site_id": site_id})
            return self._snapshot(record)

    def record_consent(
        self,
        actor: dict[str, Any],
        *,
        subject_id: str,
        protocol_version: str,
        signed_at: Any,
        consent_version: str,
        document_ref: str,
        document_checksum: str,
        consent_id: Optional[str] = None,
    ) -> dict[str, Any]:
        """登记知情同意：同意书必须对应某方案版本，留存引用与校验值。"""
        actor = self._actor(actor)
        self._require_role(actor, "研究者", "试验协调员")
        signed = _parse_dt(signed_at)
        with self._lock:
            subject = self._get(self.subjects, "受试者", subject_id)
            if subject["withdrawn"]:
                raise StateConflictError("受试者已撤回，不得登记新同意")
            proto = self._find_protocol_by_version(protocol_version)
            cid = consent_id or _new_id("icf")
            if cid in self.consents:
                raise StateConflictError(f"同意记录已存在：{cid}")
            record = {
                "consent_id": cid,
                "subject_id": subject_id,
                "protocol_id": proto["protocol_id"],
                "protocol_version": proto["version"],
                "consent_version": consent_version,
                "document_ref": document_ref,
                "document_checksum": document_checksum,
                "status": "已签署",
                "signed_at": signed.isoformat(timespec="seconds"),
                "withdrawn_at": None,
            }
            self.consents[cid] = record
            subject["consent_id"] = cid
            self._audit_log(actor, "record_consent", "consent", cid,
                            {"subject_id": subject_id,
                             "protocol_version": proto["version"]})
            return self._snapshot(record)

    def withdraw_consent(
        self, actor: dict[str, Any], *, subject_id: str, at: Any, reason: str = ""
    ) -> dict[str, Any]:
        """撤回同意：停止新增研究用途；安全相关记录依法规保留。"""
        actor = self._actor(actor)
        self._require_role(actor, "研究者", "试验协调员", "受试者")
        with self._lock:
            subject = self._get(self.subjects, "受试者", subject_id)
            if not subject["consent_id"]:
                raise StateConflictError("该受试者没有有效同意记录")
            consent = self.consents[subject["consent_id"]]
            if consent["status"] == "已撤回":
                raise StateConflictError("同意已处于撤回状态")
            at_dt = _parse_dt(at)
            consent["status"] = "已撤回"
            consent["withdrawn_at"] = at_dt.isoformat(timespec="seconds")
            subject["withdrawn"] = True
            subject["withdrawn_at"] = at_dt.isoformat(timespec="seconds")
            subject["research_use_blocked_after"] = at_dt.isoformat(timespec="seconds")
            if subject["status"] in ("筛选中",):
                subject["status"] = "已撤回"
            self._audit_log(actor, "withdraw_consent", "subject", subject_id,
                            {"reason": reason, "retained": "safety_records"})
            return self._snapshot(subject)

    def screen_eligibility(
        self,
        actor: dict[str, Any],
        *,
        subject_id: str,
        protocol_version: str,
        inclusion_met: dict[str, bool],
        exclusion_met: dict[str, bool],
        decided_at: Any,
    ) -> dict[str, Any]:
        """入排判定：所有入选标准为真且所有排除标准为假才可入组。"""
        actor = self._actor(actor)
        self._require_role(actor, "研究者")
        with self._lock:
            subject = self._get(self.subjects, "受试者", subject_id)
            if subject["withdrawn"]:
                raise StateConflictError("受试者已撤回，不得进行入排判定")
            proto = self._find_protocol_by_version(protocol_version)
            failed_inclusion = [k for k, ok in inclusion_met.items() if not ok]
            hit_exclusion = [k for k, hit in exclusion_met.items() if hit]
            eligible = not failed_inclusion and not hit_exclusion
            record = {
                "subject_id": subject_id,
                "protocol_id": proto["protocol_id"],
                "protocol_version": proto["version"],
                "inclusion_met": dict(inclusion_met),
                "exclusion_met": dict(exclusion_met),
                "eligible": eligible,
                "failed_inclusion": failed_inclusion,
                "hit_exclusion": hit_exclusion,
                "decided_at": _parse_dt(decided_at).isoformat(timespec="seconds"),
                "decided_by": actor["id"],
            }
            self.eligibility[subject_id] = record
            self._audit_log(actor, "screen_eligibility", "subject", subject_id,
                            {"eligible": eligible,
                             "failed_inclusion": failed_inclusion,
                             "hit_exclusion": hit_exclusion})
            return self._snapshot(record)

    def enroll_subject(
        self,
        actor: dict[str, Any],
        *,
        subject_id: str,
        protocol_version: str,
        at: Any,
    ) -> dict[str, Any]:
        """入组：放行方案 + 有效同意 + 入排合格 + 中心资质，四者缺一不可。"""
        actor = self._actor(actor)
        self._require_role(actor, "研究者", "试验协调员")
        with self._lock:
            subject = self._get(self.subjects, "受试者", subject_id)
            if subject["status"] != "筛选中":
                raise StateConflictError(
                    f"受试者状态为 {subject['status']}，仅筛选中可入组"
                )
            if subject["withdrawn"]:
                raise StateConflictError("受试者已撤回同意，不得入组",
                                         code="consent_withdrawn")
            proto = self._approved(self._find_protocol_by_version(protocol_version)["protocol_id"])
            self._site_can_run(subject["site_id"], proto["protocol_id"])

            consent = self.consents.get(subject["consent_id"] or "")
            if not consent or consent["status"] != "已签署":
                raise StateConflictError("缺少有效知情同意", code="missing_consent")
            if consent["protocol_version"] != proto["version"]:
                raise StateConflictError(
                    f"同意书版本 {consent['protocol_version']} 与入组方案 "
                    f"{proto['version']} 不一致",
                    code="consent_version_mismatch",
                )
            screen = self.eligibility.get(subject_id)
            if screen is None:
                raise StateConflictError("尚未完成入排判定", code="eligibility_missing")
            if screen["protocol_version"] != proto["version"]:
                raise StateConflictError(
                    "入排判定所依据的方案版本与入组版本不一致，需按新版本重新判定",
                    code="eligibility_version_mismatch",
                )
            if not screen["eligible"]:
                raise StateConflictError(
                    f"受试者不符合入排条件（入选失败：{screen['failed_inclusion']}；"
                    f"命中排除：{screen['hit_exclusion']}）",
                    code="subject_ineligible",
                )
            at_dt = _parse_dt(at)
            if _parse_dt(consent["signed_at"]) > at_dt:
                raise StateConflictError("入组时间早于同意签署时间")
            subject["status"] = "已入组"
            subject["protocol_id"] = proto["protocol_id"]
            subject["protocol_version"] = proto["version"]
            subject["enrolled_at"] = at_dt.isoformat(timespec="seconds")
            self._audit_log(actor, "enroll_subject", "subject", subject_id,
                            {"protocol_version": proto["version"], "at": subject["enrolled_at"]})
            return self._snapshot(subject)

    # ----- 批次与剂量队列 -----------------------------------------------

    def register_lot(
        self,
        actor: dict[str, Any],
        *,
        lot_id: str,
        kind: str,
        product: str,
        expires_at: Any,
    ) -> dict[str, Any]:
        """登记药物/器械批次。kind 为 药物 或 器械（如激光光纤球囊）。"""
        actor = self._actor(actor)
        self._require_role(actor, "试验协调员")
        if kind not in ("药物", "器械"):
            raise ValidationError("批次类别必须是 药物 或 器械")
        if lot_id in self.lots:
            raise StateConflictError(f"批次已存在：{lot_id}", code="duplicate_lot")
        record = {
            "lot_id": lot_id,
            "kind": kind,
            "product": product,
            "status": "合格",
            "expires_at": _parse_dt(expires_at).isoformat(timespec="seconds"),
        }
        with self._lock:
            self.lots[lot_id] = record
            self._audit_log(actor, "register_lot", "lot", lot_id,
                            {"kind": kind, "product": product})
            return self._snapshot(record)

    def change_lot_status(
        self, actor: dict[str, Any], *, lot_id: str, status: str, reason: str
    ) -> dict[str, Any]:
        actor = self._actor(actor)
        self._require_role(actor, "试验协调员", "安全委员会")
        if status not in LOT_STATUSES:
            raise ValidationError(f"批次状态必须是：{'、'.join(LOT_STATUSES)}")
        with self._lock:
            record = self._get(self.lots, "批次", lot_id)
            record["status"] = status
            self._audit_log(actor, "change_lot_status", "lot", lot_id,
                            {"status": status, "reason": reason})
            return self._snapshot(record)

    def _lot_ready(self, lot_id: str) -> dict[str, Any]:
        lot = self._get(self.lots, "批次", lot_id)
        if lot["status"] != "合格":
            raise StateConflictError(
                f"{lot['kind']}批次 {lot_id} 状态为 {lot['status']}，不得使用",
                code="lot_not_available",
            )
        if _parse_dt(lot["expires_at"]) < self._now():
            raise StateConflictError(f"批次 {lot_id} 已过期", code="lot_expired")
        return lot

    def create_cohort(
        self,
        actor: dict[str, Any],
        *,
        cohort_id: str,
        protocol_version: str,
        drug_dose: str,
        light_fluence: str,
        light_schedule: str,
        capacity: int,
    ) -> dict[str, Any]:
        """剂量队列：剂量（药物剂量+光通量+照射方案）绑定到具体方案版本。"""
        actor = self._actor(actor)
        self._require_role(actor, "研究者", "试验协调员")
        if int(capacity) <= 0:
            raise ValidationError("队列容量必须为正整数")
        with self._lock:
            if cohort_id in self.cohorts:
                raise StateConflictError(f"队列已存在：{cohort_id}", code="duplicate_cohort")
            proto = self._find_protocol_by_version(protocol_version)
            record = {
                "cohort_id": cohort_id,
                "protocol_id": proto["protocol_id"],
                "protocol_version": proto["version"],
                "drug_dose": drug_dose,
                "light_fluence": light_fluence,
                "light_schedule": light_schedule,
                "capacity": int(capacity),
                "enrolled": 0,
                "status": "招募中",
            }
            self.cohorts[cohort_id] = record
            self._audit_log(actor, "create_cohort", "cohort", cohort_id,
                            {"protocol_version": proto["version"],
                             "drug_dose": drug_dose, "light_fluence": light_fluence})
            return self._snapshot(record)

    def assign_cohort(
        self, actor: dict[str, Any], *, subject_id: str, cohort_id: str, at: Any
    ) -> dict[str, Any]:
        """分配剂量队列（对盲态角色保密）：方案须匹配且队列有容量。"""
        actor = self._actor(actor)
        self._require_role(actor, "研究者", "试验协调员")
        with self._lock:
            subject = self._get(self.subjects, "受试者", subject_id)
            cohort = self._get(self.cohorts, "队列", cohort_id)
            if subject["status"] != "已入组":
                raise StateConflictError("仅已入组受试者可分配队列")
            if cohort["protocol_id"] != subject["protocol_id"]:
                raise StateConflictError(
                    f"队列属于方案 {cohort['protocol_version']}，受试者入组方案为 "
                    f"{subject['protocol_version']}，剂量混淆被阻止",
                    code="dose_protocol_mismatch",
                )
            if subject["cohort_id"]:
                raise StateConflictError("受试者已分配队列，不得跨队列混淆剂量",
                                         code="cohort_reassignment")
            if cohort["status"] != "招募中" or cohort["enrolled"] >= cohort["capacity"]:
                raise StateConflictError(f"队列 {cohort_id} 无可用名额",
                                         code="cohort_full")
            at_iso = _parse_dt(at).isoformat(timespec="seconds")
            record = {
                "subject_id": subject_id,
                "cohort_id": cohort_id,
                "assigned_at": at_iso,
                "assigned_by": actor["id"],
                "drug_dose": cohort["drug_dose"],
                "light_fluence": cohort["light_fluence"],
                "light_schedule": cohort["light_schedule"],
            }
            self.assignments[subject_id] = record
            cohort["enrolled"] += 1
            if cohort["enrolled"] >= cohort["capacity"]:
                cohort["status"] = "已满员"
            subject["cohort_id"] = cohort_id
            self._audit_log(actor, "assign_cohort", "subject", subject_id,
                            {"cohort_id": cohort_id})
            return self._snapshot(record)

    # ----- 紧急偏离 ------------------------------------------------------

    def declare_emergency_deviation(
        self,
        actor: dict[str, Any],
        *,
        subject_id: str,
        at: Any,
        deviation_type: str,
        reason: str,
        target_kind: Optional[str] = None,
        target_planned_at: Any = None,
        target_activity_id: Optional[str] = None,
    ) -> dict[str, Any]:
        """紧急偏离可先行处置：登记后允许其声明的那一次治疗活动先执行，
        但必须及时补录原因并经安全委员会复核；其他研究活动仍被阻断。

        deviation_type:
          - 治疗前紧急处置：在方案未放行等情况下先行救治。可直接传 target_kind 与
            target_planned_at 生成被该偏离覆盖的活动（跳过常规排程闸门）；
          - 治疗中方案偏离：给药/照光时序等紧急调整，须关联已排程活动。
        """
        actor = self._actor(actor)
        self._require_role(actor, "研究者")
        if deviation_type not in ("治疗前紧急处置", "治疗中方案偏离"):
            raise ValidationError("未知紧急偏离类型")
        with self._lock:
            subject = self._get(self.subjects, "受试者", subject_id)
            if subject["withdrawn"]:
                raise StateConflictError("受试者已撤回，不得登记研究性紧急偏离")
            if subject["status"] not in ("已入组", "治疗中"):
                raise StateConflictError(
                    "紧急偏离仅适用于已入组受试者；未入组者应先完成放行方案下的入组流程",
                    code="not_enrolled",
                )
            if self._open_sae(subject_id) is not None:
                raise StateConflictError(
                    "存在未复核 SAE，治疗活动冻结至安全委员会复核，"
                    "紧急偏离不能覆盖 SAE 冻结",
                    code="sae_hold",
                )
            if deviation_type == "治疗中方案偏离" and not target_activity_id:
                raise ValidationError("治疗中方案偏离必须关联已排程的目标活动")
            aid: Optional[str] = target_activity_id
            if target_activity_id:
                target = self._get(self.activities, "活动", target_activity_id)
                if target["subject_id"] != subject_id:
                    raise ValidationError("目标活动与偏离不属于同一受试者")
                if target["kind"] not in TREATMENT_ACTIVITIES:
                    raise ValidationError("紧急偏离只能覆盖治疗类活动")
            elif deviation_type == "治疗前紧急处置":
                if target_kind is None or target_planned_at is None:
                    raise ValidationError(
                        "治疗前紧急处置须提供 target_kind 与 target_planned_at"
                    )
                if target_kind not in TREATMENT_ACTIVITIES:
                    raise ValidationError("紧急偏离只能覆盖治疗类活动")
                aid = _new_id("act")
                self.activities[aid] = {
                    "activity_id": aid,
                    "subject_id": subject_id,
                    "kind": target_kind,
                    "planned_at": _parse_dt(target_planned_at).isoformat(timespec="seconds"),
                    "status": "已排程",
                    "outcome": None,
                    "actual_at": None,
                    "lot_id": None,
                    "device_lot_id": None,
                    "actual_dose": None,
                    "emergency_deviation_id": None,
                    "parent_activity_id": None,
                    "notes": "由紧急偏离先行处置生成",
                }
            did = _new_id("dev")
            record = {
                "deviation_id": did,
                "subject_id": subject_id,
                "type": deviation_type,
                "reason": reason,
                "status": "待复核" if reason.strip() else "待补录原因",
                "declared_at": _parse_dt(at).isoformat(timespec="seconds"),
                "declared_by": actor["id"],
                "target_activity_id": aid,
                "justification": reason if reason.strip() else "",
                "review": None,
            }
            self.deviations[did] = record
            if aid:
                self.activities[aid]["emergency_deviation_id"] = did
            self._audit_log(actor, "declare_emergency_deviation", "deviation", did,
                            {"subject_id": subject_id, "type": deviation_type,
                             "target_activity_id": aid})
            return self._snapshot(record)

    def supplement_deviation(
        self, actor: dict[str, Any], *, deviation_id: str, justification: str
    ) -> dict[str, Any]:
        """补录紧急偏离的原因（先行处置后限时补录的留痕动作）。"""
        actor = self._actor(actor)
        self._require_role(actor, "研究者", "试验协调员")
        if not justification.strip():
            raise ValidationError("补录原因不得为空")
        with self._lock:
            record = self._get(self.deviations, "偏离", deviation_id)
            if record["review"]:
                raise StateConflictError("该偏离已完成复核，不得再修改")
            record["justification"] = justification
            record["status"] = "待复核"
            self._audit_log(actor, "supplement_deviation", "deviation", deviation_id)
            return self._snapshot(record)

    def review_deviation(
        self,
        actor: dict[str, Any],
        *,
        deviation_id: str,
        accepted: bool,
        committee_comment: str,
    ) -> dict[str, Any]:
        actor = self._actor(actor)
        self._require_role(actor, "安全委员会")
        with self._lock:
            record = self._get(self.deviations, "偏离", deviation_id)
            if record["status"] == "待补录原因":
                raise StateConflictError("偏离原因尚未补录，不能复核")
            review = {
                "accepted": bool(accepted),
                "comment": committee_comment,
                "reviewed_by": actor["id"],
                "at": self._now().isoformat(timespec="seconds"),
            }
            record["review"] = review
            record["status"] = "安全委员会已复核"
            self._audit_log(actor, "review_deviation", "deviation", deviation_id, review)
            return self._snapshot(record)

    # ----- SAE -----------------------------------------------------------

    def report_sae(
        self,
        actor: dict[str, Any],
        *,
        subject_id: str,
        at: Any,
        description: str,
        severity: str,
        related_activity_id: Optional[str] = None,
    ) -> dict[str, Any]:
        """登记严重不良事件。登记即冻结该受试者后续研究活动，直至安全委员会复核。"""
        actor = self._actor(actor)
        self._require_role(actor, "研究者", "试验协调员")
        if severity not in ("轻度", "中度", "重度", "危及生命", "死亡"):
            raise ValidationError("SAE 严重等级不合法")
        with self._lock:
            self._get(self.subjects, "受试者", subject_id)
            sid = _new_id("sae")
            record = {
                "sae_id": sid,
                "subject_id": subject_id,
                "status": "已报告",
                "description": description,
                "severity": severity,
                "occurred_at": _parse_dt(at).isoformat(timespec="seconds"),
                "reported_by": actor["id"],
                "reported_at": self._now().isoformat(timespec="seconds"),
                "related_activity_id": related_activity_id,
                "review": None,
            }
            self.saes[sid] = record
            self._audit_log(actor, "report_sae", "sae", sid,
                            {"subject_id": subject_id, "severity": severity})
            return self._snapshot(record)

    def review_sae(
        self,
        actor: dict[str, Any],
        *,
        sae_id: str,
        decision: str,
        rationale: str,
    ) -> dict[str, Any]:
        """安全委员会复核 SAE 并给出继续/暂停入组/终止决议。"""
        actor = self._actor(actor)
        self._require_role(actor, "安全委员会")
        if decision not in DECISION_STATUSES:
            raise ValidationError(f"决议必须是：{'、'.join(DECISION_STATUSES)}")
        with self._lock:
            record = self._get(self.saes, "SAE", sae_id)
            if record["status"] in ("安全委员会已复核", "已关闭"):
                raise StateConflictError("SAE 已复核")
            review = {
                "decision": decision,
                "rationale": rationale,
                "reviewed_by": actor["id"],
                "at": self._now().isoformat(timespec="seconds"),
            }
            record["review"] = review
            record["status"] = "安全委员会已复核" if decision == "继续" else "已关闭"
            self.decisions.append(
                {"scope": "sae", "target_id": sae_id, **review}
            )
            if decision == "终止":
                subject = self.subjects[record["subject_id"]]
                if subject["status"] not in ("已撤回",):
                    subject["status"] = "已撤回"
                    subject["withdrawn"] = True
                    subject["withdrawn_at"] = review["at"]
                    subject["research_use_blocked_after"] = review["at"]
            self._audit_log(actor, "review_sae", "sae", sae_id, review)
            return self._snapshot(record)

    def _open_sae(self, subject_id: str) -> Optional[dict[str, Any]]:
        for sae in self.saes.values():
            if sae["subject_id"] == subject_id and sae["status"] == "已报告":
                return sae
        return None

    # ----- 操作时间线 ----------------------------------------------------

    def _blocking_emergency(self, subject_id: str) -> Optional[dict[str, Any]]:
        """治疗前紧急处置仅覆盖它自己声明的那次活动，其他研究活动一律阻断，
        直至补录原因并经安全委员会复核。"""
        for dev in self.deviations.values():
            if dev["subject_id"] != subject_id:
                continue
            if dev["type"] != "治疗前紧急处置":
                continue
            if dev["review"]:
                continue
            return dev
        return None

    def _emergency_review_gate(
        self, subject_id: str, allowed_activity_id: Optional[str] = None
    ) -> None:
        """除紧急偏离声明的目标活动外，未复核期间冻结其他新增研究活动。"""
        emergency = self._blocking_emergency(subject_id)
        if emergency is None:
            return
        if allowed_activity_id is not None and emergency.get("target_activity_id") == allowed_activity_id:
            return
        raise StateConflictError(
            f"存在未复核的治疗前紧急偏离 {emergency['deviation_id']}，"
            "除其声明的先行处置外不得开展其他研究活动；须先补录原因并经安全委员会复核",
            code="emergency_deviation_open",
        )

    def schedule_activity(
        self,
        actor: dict[str, Any],
        *,
        subject_id: str,
        kind: str,
        planned_at: Any,
        activity_id: Optional[str] = None,
    ) -> dict[str, Any]:
        """排程研究活动（注射/激光照射/手术评估/影像/病理/访视）。

        治疗类活动排程即校验：方案放行、中心资质、批次不涉及（执行时校验）、
        SAE 冻结、撤回与越窗。
        """
        actor = self._actor(actor)
        self._require_role(actor, "研究者", "试验协调员")
        if kind not in VISIT_KINDS:
            raise ValidationError(f"活动类型必须是：{'、'.join(VISIT_KINDS)}")
        with self._lock:
            subject = self._get(self.subjects, "受试者", subject_id)
            planned = _parse_dt(planned_at)
            if subject["withdrawn"]:
                raise StateConflictError("受试者已撤回，不得新增研究活动",
                                         code="subject_withdrawn")
            if kind in TREATMENT_ACTIVITIES:
                self._treatment_gate(subject, at=planned, for_scheduling=True)
            else:
                self._emergency_review_gate(subject_id)
                if kind in ("手术评估", "影像采集", "病理采集", "访视"):
                    self._window_gate(subject, planned)
            aid = activity_id or _new_id("act")
            if aid in self.activities:
                raise StateConflictError(f"活动已存在：{aid}")
            record = {
                "activity_id": aid,
                "subject_id": subject_id,
                "kind": kind,
                "planned_at": planned.isoformat(timespec="seconds"),
                "status": "已排程",
                "outcome": None,
                "actual_at": None,
                "lot_id": None,
                "device_lot_id": None,
                "actual_dose": None,
                "emergency_deviation_id": None,
                "parent_activity_id": None,
                "notes": "",
            }
            self.activities[aid] = record
            self._audit_log(actor, "schedule_activity", "activity", aid,
                            {"subject_id": subject_id, "kind": kind,
                             "planned_at": record["planned_at"]})
            return self._snapshot(record)

    def _treatment_gate(
        self, subject: dict[str, Any], *, at: datetime, for_scheduling: bool,
        check_emergency: bool = True,
    ) -> None:
        """治疗前阻断规则：错误方案/SAE/撤回/未分配队列一律阻止。

        执行紧急偏离的目标活动时由调用方传 check_emergency=False 自行豁免。
        """
        sid = subject["subject_id"]
        if subject["withdrawn"]:
            raise StateConflictError("受试者已撤回，治疗活动被阻止",
                                     code="subject_withdrawn")
        open_sae = self._open_sae(sid)
        if open_sae:
            raise StateConflictError(
                f"存在未复核 SAE {open_sae['sae_id']}，治疗活动冻结至安全委员会复核",
                code="sae_hold",
            )
        if subject["status"] not in ("已入组", "治疗中"):
            raise StateConflictError(
                f"受试者状态为 {subject['status']}，不能安排治疗",
                code="wrong_subject_state",
            )
        proto = self._approved(subject["protocol_id"])
        self._site_can_run(subject["site_id"], proto["protocol_id"])
        if sid not in self.assignments:
            raise StateConflictError("尚未分配剂量队列，不能给药/照光",
                                     code="cohort_missing")
        if check_emergency and self._blocking_emergency(sid) is not None:
            raise StateConflictError(
                "存在未复核的治疗前紧急偏离，除其声明的先行处置外"
                "不得安排其他治疗活动",
                code="emergency_deviation_open",
            )

    def _window_gate(self, subject: dict[str, Any], at: datetime) -> None:
        window = subject.get("window")
        if window is None:
            # 尚未治疗，无观察窗可言
            return
        start = _parse_dt(window["start_at"])
        end = _parse_dt(window["end_at"])
        if at < start or at > end:
            raise StateConflictError(
                f"时间 {at.isoformat(timespec='seconds')} 越出观察窗 "
                f"{window['start_at']} ~ {window['end_at']}（方案 {subject['protocol_version']}，"
                f"{self.protocols[subject['protocol_id']]['observation_days']} 天）",
                code="outside_window",
            )

    def perform_activity(
        self,
        actor: dict[str, Any],
        *,
        activity_id: str,
        at: Any,
        drug_lot_id: Optional[str] = None,
        device_lot_id: Optional[str] = None,
        actual_dose: Optional[dict[str, Any]] = None,
        outcome: str = "按计划完成",
        linked_activity_id: Optional[str] = None,
        notes: str = "",
        emergency_deviation_id: Optional[str] = None,
    ) -> dict[str, Any]:
        """执行活动：批次校验、实际剂量记录、给药→照光时序、器械更换/延后处理。

        器械更换：以 outcome=器械更换 关闭原活动，并通过 linked_activity_id
        生成一条替代活动（新批次），两条记录互相链接用于溯源。
        术期延后：outcome=术期延后，活动不计为治疗事实，须另行排程。
        """
        actor = self._actor(actor)
        self._require_role(actor, "研究者")
        if outcome not in ACTIVITY_OUTCOMES:
            raise ValidationError(f"活动结局必须是：{'、'.join(ACTIVITY_OUTCOMES)}")
        with self._lock:
            record = self._get(self.activities, "活动", activity_id)
            subject = self._get(self.subjects, "受试者", record["subject_id"])
            at_dt = _parse_dt(at)
            kind = record["kind"]

            if record["status"] == "已完成":
                raise StateConflictError("活动已完成，不得重复执行",
                                         code="activity_closed")
            if subject["withdrawn"] and kind in TREATMENT_ACTIVITIES:
                raise StateConflictError("受试者已撤回，治疗活动被阻止",
                                         code="subject_withdrawn")

            emergency = None
            if emergency_deviation_id:
                emergency = self._get(self.deviations, "偏离", emergency_deviation_id)
                if emergency["subject_id"] != subject["subject_id"]:
                    raise ValidationError("紧急偏离与活动不属于同一受试者")
                if emergency["review"]:
                    raise StateConflictError("该紧急偏离已复核，应回归正常方案流程")

            if kind in TREATMENT_ACTIVITIES:
                # SAE 冻结对治疗活动绝对生效（紧急偏离不能覆盖 SAE 冻结）
                open_sae = self._open_sae(subject["subject_id"])
                if open_sae:
                    raise StateConflictError(
                        f"存在未复核 SAE {open_sae['sae_id']}，治疗活动冻结",
                        code="sae_hold",
                    )
                if emergency is not None:
                    target = emergency.get("target_activity_id")
                    if target is not None and target != activity_id:
                        raise StateConflictError(
                            "紧急偏离仅覆盖其声明的目标活动",
                            code="emergency_target_mismatch",
                        )
                    if emergency["type"] == "治疗前紧急处置":
                        # 豁免方案放行/队列等常规闸门（撤回与 SAE 已在前面拦截）
                        pass
                    elif emergency["type"] == "治疗中方案偏离":
                        # 常规闸门仍生效，仅给药→照光时序/剂量一致性由其豁免
                        self._treatment_gate(subject, at=at_dt, for_scheduling=False)
                    else:
                        raise StateConflictError(
                            "该紧急偏离类型不能豁免治疗前阻断",
                            code="emergency_type_mismatch",
                        )
                else:
                    if self._blocking_emergency(subject["subject_id"]) is not None:
                        raise StateConflictError(
                            "存在未复核的治疗前紧急偏离，须凭该偏离执行其目标活动",
                            code="emergency_deviation_open",
                        )
                    self._treatment_gate(subject, at=at_dt, for_scheduling=False)

            # 术期延后：不消耗批次、不构成治疗事实
            if outcome == "术期延后":
                record["status"] = "已完成"
                record["outcome"] = "术期延后"
                record["actual_at"] = at_dt.isoformat(timespec="seconds")
                record["notes"] = notes
                self._audit_log(actor, "perform_activity", "activity", activity_id,
                                {"outcome": "术期延后"})
                return self._snapshot(record)

            if outcome == "取消":
                record["status"] = "已完成"
                record["outcome"] = "取消"
                record["actual_at"] = at_dt.isoformat(timespec="seconds")
                record["notes"] = notes
                self._audit_log(actor, "perform_activity", "activity", activity_id,
                                {"outcome": "取消"})
                return self._snapshot(record)

            # 实际执行：批次校验
            if kind == "注射":
                if not drug_lot_id:
                    raise ValidationError("注射活动必须登记药物批次")
                lot = self._lot_ready(drug_lot_id)
                if lot["kind"] != "药物":
                    raise StateConflictError("注射活动必须使用药物批次",
                                             code="lot_kind_mismatch")
                record["lot_id"] = drug_lot_id
            if kind == "激光照射":
                if not device_lot_id:
                    raise ValidationError("激光照射必须登记光纤球囊器械批次")
                lot = self._get(self.lots, "批次", device_lot_id)
                if lot["kind"] != "器械":
                    raise StateConflictError("激光照射必须使用器械批次",
                                             code="lot_kind_mismatch")
                # 器械更换是对故障事实的留痕：允许引用已隔离/召回的故障批次，
                # 但真正完成照光时批次必须合格（下方分支之后再校验）。
                if outcome != "器械更换":
                    self._lot_ready(device_lot_id)
                record["device_lot_id"] = device_lot_id

            # 器械更换：关闭原活动（不构成照光事实），必须指向替代活动
            if outcome == "器械更换":
                if kind != "激光照射":
                    raise ValidationError("仅激光照射活动可登记器械更换")
                if not linked_activity_id:
                    raise ValidationError("器械更换必须指定替代活动（linked_activity_id）")
                replacement = self._get(self.activities, "活动", linked_activity_id)
                if replacement["subject_id"] != subject["subject_id"]:
                    raise ValidationError("替代活动不属于同一受试者")
                if replacement["kind"] != "激光照射":
                    raise ValidationError("替代活动必须是激光照射")
                if replacement["status"] != "已排程":
                    raise StateConflictError("替代活动必须处于已排程状态")
                record["status"] = "已完成"
                record["outcome"] = "器械更换"
                record["actual_at"] = at_dt.isoformat(timespec="seconds")
                record["device_lot_id"] = device_lot_id
                record["notes"] = notes
                replacement["parent_activity_id"] = activity_id
                self._audit_log(actor, "device_swap", "activity", activity_id,
                                {"replacement": linked_activity_id,
                                 "failed_lot": device_lot_id})
                return self._snapshot(record)

            # 正常完成
            record["status"] = "已完成"
            record["outcome"] = "按计划完成"
            record["actual_at"] = at_dt.isoformat(timespec="seconds")
            record["notes"] = notes

            if kind == "注射":
                assignment = self.assignments.get(subject["subject_id"])
                if assignment is None:
                    # 紧急先行处置没有队列分配，实际剂量必须由操作者显式记录
                    if not actual_dose or not actual_dose.get("drug_dose"):
                        raise ValidationError(
                            "紧急先行处置必须显式记录实际药物剂量"
                        )
                    drug_dose = actual_dose["drug_dose"]
                else:
                    given = actual_dose or {}
                    drug_dose = given.get("drug_dose", assignment["drug_dose"])
                record["actual_dose"] = {"drug_dose": drug_dose}
                subject["status"] = "治疗中"
                if subject["treatment_at"] is None:
                    subject["treatment_at"] = record["actual_at"]
            elif kind == "激光照射":
                self._check_light_timing(subject, at_dt, actual_dose, emergency)
                assignment = self.assignments.get(subject["subject_id"])
                given = actual_dose or {}
                if assignment is None:
                    if not given.get("light_fluence") or not given.get("light_schedule"):
                        raise ValidationError(
                            "紧急先行处置必须显式记录实际光通量与照射方案"
                        )
                    record["actual_dose"] = {
                        "light_fluence": given["light_fluence"],
                        "light_schedule": given["light_schedule"],
                    }
                else:
                    record["actual_dose"] = {
                        "light_fluence": given.get("light_fluence", assignment["light_fluence"]),
                        "light_schedule": given.get("light_schedule", assignment["light_schedule"]),
                    }
                self._open_observation_window(subject, at_dt, emergency)

            self._audit_log(actor, "perform_activity", "activity", activity_id,
                            {"outcome": record["outcome"],
                             "actual_dose": record["actual_dose"]})
            return self._snapshot(record)

    def _check_light_timing(
        self,
        subject: dict[str, Any],
        at: datetime,
        actual_dose: Optional[dict[str, Any]],
        emergency: Optional[dict[str, Any]] = None,
    ) -> None:
        """校验给药→照光间隔落在方案窗口。

        治疗中方案偏离经登记后可先行执行（间隔/剂量不一致不再阻断），
        但实际剂量必须显式记录，事后补录原因并由安全委员会复核。
        """
        injections = [
            a for a in self.activities.values()
            if a["subject_id"] == subject["subject_id"]
            and a["kind"] == "注射"
            and a["outcome"] == "按计划完成"
        ]
        if not injections:
            raise StateConflictError("尚无完成的注射记录，不能照光",
                                     code="drug_light_order")
        last_injection = max(injections, key=lambda a: a["actual_at"])
        delta_minutes = (at - _parse_dt(last_injection["actual_at"])).total_seconds() / 60
        given = actual_dose or {}

        if emergency is not None:
            # 任一紧急偏离下先行照光：时序/剂量一致性豁免，但实际剂量必须显式留痕，
            # 事后补录原因并由安全委员会复核。
            if not given.get("light_fluence") or not given.get("light_schedule"):
                raise ValidationError(
                    "紧急偏离下照光必须显式记录实际光通量与照射方案"
                )
            return

        proto = self.protocols[subject["protocol_id"]]
        lo = proto["drug_to_light"]["min_minutes"]
        hi = proto["drug_to_light"]["max_minutes"]
        if not (lo <= delta_minutes <= hi):
            raise StateConflictError(
                f"给药→照光间隔 {delta_minutes:.0f} 分钟越出方案窗口 {lo}~{hi} 分钟；"
                "如需紧急调整须先登记治疗中方案偏离并经复核",
                code="drug_light_interval",
            )
        assignment = self.assignments[subject["subject_id"]]
        if given.get("light_fluence", assignment["light_fluence"]) != assignment["light_fluence"] or given.get(
            "light_schedule", assignment["light_schedule"]
        ) != assignment["light_schedule"]:
            raise StateConflictError(
                "实际光剂量/照射方案与分配队列不一致，剂量混淆被阻止；"
                "紧急调整须登记治疗中方案偏离",
                code="dose_mismatch",
            )

    def _open_observation_window(
        self, subject: dict[str, Any], at: datetime,
        emergency: Optional[dict[str, Any]] = None,
    ) -> None:
        proto = self.protocols[subject["protocol_id"]]
        days = proto["observation_days"]
        subject["window"] = {
            "start_at": at.isoformat(timespec="seconds"),
            "end_at": (at + timedelta(days=days)).isoformat(timespec="seconds"),
            "observation_days": days,
            "basis": "激光照射完成时间",
            "opened_via_deviation": None if emergency is None else emergency["deviation_id"],
        }
        subject["status"] = "观察中"

    def delay_activity(
        self, actor: dict[str, Any], *, activity_id: str, new_planned_at: Any, reason: str
    ) -> dict[str, Any]:
        """术期延后改排：保留原活动与原因，重设计划时间并重新过窗校验。"""
        actor = self._actor(actor)
        self._require_role(actor, "研究者", "试验协调员")
        with self._lock:
            record = self._get(self.activities, "活动", activity_id)
            if record["status"] != "已排程":
                raise StateConflictError("仅已排程活动可改期")
            subject = self._get(self.subjects, "受试者", record["subject_id"])
            new_at = _parse_dt(new_planned_at)
            if record["kind"] in TREATMENT_ACTIVITIES:
                self._treatment_gate(subject, at=new_at, for_scheduling=True)
            else:
                self._window_gate(subject, new_at)
            old = record["planned_at"]
            record["planned_at"] = new_at.isoformat(timespec="seconds")
            record.setdefault("reschedule_history", []).append(
                {"from": old, "to": record["planned_at"], "reason": reason,
                 "by": actor["id"], "at": self._now().isoformat(timespec="seconds")}
            )
            self._audit_log(actor, "delay_activity", "activity", activity_id,
                            {"from": old, "to": record["planned_at"], "reason": reason})
            return self._snapshot(record)

    # ----- 影像与病理（去标识化引用 + 校验值） --------------------------

    def register_artifact(
        self,
        actor: dict[str, Any],
        *,
        subject_id: str,
        artifact_type: str,
        ref: str,
        checksum: str,
        captured_at: Any,
        linked_activity_id: Optional[str] = None,
        free_text: str = "",
        artifact_id: Optional[str] = None,
    ) -> dict[str, Any]:
        """登记影像/病理：只存去标识化引用与校验值，不接收原始影像/病理内容。"""
        actor = self._actor(actor)
        self._require_role(actor, "研究者", "试验协调员", "盲态评价者")
        if artifact_type not in ("影像", "病理"):
            raise ValidationError("采集物类型必须是 影像 或 病理")
        if not str(ref).strip():
            raise ValidationError("必须提供去标识化引用（如受控存储区 URI）")
        if not str(checksum).strip():
            raise ValidationError("必须提供校验值")
        with self._lock:
            subject = self._get(self.subjects, "受试者", subject_id)
            captured = _parse_dt(captured_at)
            if subject["withdrawn"] and (
                subject["research_use_blocked_after"] is not None
                and captured > _parse_dt(subject["research_use_blocked_after"])
            ):
                raise StateConflictError(
                    "撤回同意后不得新增研究用途采集；安全记录保留流程另行处理",
                    code="research_use_blocked",
                )
            self._emergency_review_gate(subject_id)
            self._window_gate(subject, captured)
            aid = artifact_id or _new_id("art")
            record = {
                "artifact_id": aid,
                "subject_id": subject_id,
                "artifact_type": artifact_type,
                "ref": ref,
                "checksum": checksum,
                "captured_at": captured.isoformat(timespec="seconds"),
                "linked_activity_id": linked_activity_id,
                "free_text": _redact_pii_text(free_text),
                "registered_by": actor["id"],
            }
            self.artifacts[aid] = record
            self._audit_log(actor, "register_artifact", "artifact", aid,
                            {"subject_id": subject_id, "type": artifact_type})
            return self._snapshot(record)

    def verify_artifact_checksum(
        self, actor: dict[str, Any], *, artifact_id: str, blob: bytes
    ) -> dict[str, Any]:
        """用校验值核对采集物副本（调用方只把字节送入内存比对，不入库）。"""
        actor = self._actor(actor)
        with self._lock:
            record = self._get(self.artifacts, "采集物", artifact_id)
            actual = _checksum(blob)
            ok = actual == record["checksum"]
            self._audit_log(actor, "verify_artifact", "artifact", artifact_id,
                            {"match": ok})
            return {"artifact_id": artifact_id, "expected": record["checksum"],
                    "actual": actual, "match": ok}

    # ----- 可评估性与结局 -----------------------------------------------

    def set_evaluability(
        self,
        actor: dict[str, Any],
        *,
        subject_id: str,
        evaluable: bool,
        reason: str,
    ) -> dict[str, Any]:
        actor = self._actor(actor)
        self._require_role(actor, "研究者", "安全委员会")
        with self._lock:
            subject = self._get(self.subjects, "受试者", subject_id)
            if subject["window"] is None:
                raise StateConflictError("观察窗尚未开启，不能判定可评估性")
            subject["evaluable"] = bool(evaluable)
            subject["evaluable_reason"] = reason
            self._audit_log(actor, "set_evaluability", "subject", subject_id,
                            {"evaluable": evaluable, "reason": reason})
            return self._snapshot(subject)

    def record_outcome(
        self,
        actor: dict[str, Any],
        *,
        subject_id: str,
        outcome_type: str,
        result_summary: str,
        at: Any,
        artifact_ids: Optional[list[str]] = None,
        resectable: Optional[bool] = None,
    ) -> dict[str, Any]:
        """登记结局（影像/病理/手术切除评估）。

        结局必须可追溯到：获批方案版本、实际剂量、器械批次与医学决定（审计链）。
        观察窗外的结局登记将被阻止，以免污染两周评估结论。
        """
        actor = self._actor(actor)
        self._require_role(actor, "研究者", "安全委员会")
        if outcome_type not in OUTCOME_TYPES:
            raise ValidationError(f"结局类型必须是：{'、'.join(OUTCOME_TYPES)}")
        with self._lock:
            subject = self._get(self.subjects, "受试者", subject_id)
            at_dt = _parse_dt(at)
            self._emergency_review_gate(subject_id)
            self._window_gate(subject, at_dt)
            if outcome_type == "手术切除评估" and resectable is None:
                raise ValidationError("手术切除评估必须给出 resectable 结论")

            linked: list[str] = []
            for aid in artifact_ids or []:
                artifact = self._get(self.artifacts, "采集物", aid)
                if artifact["subject_id"] != subject_id:
                    raise ValidationError("采集物与受试者不匹配")
                linked.append(aid)

            # 组装溯源：方案（含放行决议）、实际剂量、器械、关键医学决定
            proto = self.protocols[subject["protocol_id"]]
            chain = self._provenance_chain(subject)
            oid = _new_id("out")
            record = {
                "outcome_id": oid,
                "subject_id": subject_id,
                "outcome_type": outcome_type,
                "result_summary": _redact_pii_text(result_summary),
                "resectable": resectable,
                "at": at_dt.isoformat(timespec="seconds"),
                "artifact_ids": linked,
                "recorded_by": actor["id"],
                "provenance": chain,
            }
            self.outcomes[oid] = record
            if outcome_type == "手术切除评估" and subject["status"] == "观察中":
                subject["status"] = "可评估"
            self._audit_log(actor, "record_outcome", "outcome", oid,
                            {"subject_id": subject_id, "type": outcome_type,
                             "protocol_version": proto["version"]})
            return self._snapshot(record)

    def _provenance_chain(self, subject: dict[str, Any]) -> dict[str, Any]:
        sid = subject["subject_id"]
        proto = self.protocols[subject["protocol_id"]]
        assignment = self.assignments.get(sid)
        activities = []
        for act in self.activities.values():
            if act["subject_id"] != sid or act["status"] != "已完成":
                continue
            activities.append({
                "activity_id": act["activity_id"],
                "kind": act["kind"],
                "outcome": act["outcome"],
                "actual_at": act["actual_at"],
                "lot_id": act["lot_id"],
                "device_lot_id": act["device_lot_id"],
                "actual_dose": act["actual_dose"],
                "parent_activity_id": act["parent_activity_id"],
            })
        activities.sort(key=lambda a: a["actual_at"] or "")
        sae_ids = [s["sae_id"] for s in self.saes.values() if s["subject_id"] == sid]
        deviation_ids = [d["deviation_id"] for d in self.deviations.values()
                         if d["subject_id"] == sid]
        decisions = [d for d in self.decisions
                     if d["target_id"] in (proto["protocol_id"], *sae_ids)]
        return {
            "protocol": {
                "protocol_id": proto["protocol_id"],
                "version": proto["version"],
                "status": proto["status"],
                "approval": proto["approval"],
            },
            "cohort": None if assignment is None else {
                "cohort_id": assignment["cohort_id"],
                "assigned_dose": {
                    "drug_dose": assignment["drug_dose"],
                    "light_fluence": assignment["light_fluence"],
                    "light_schedule": assignment["light_schedule"],
                },
                "assigned_at": assignment["assigned_at"],
            },
            "activities": activities,
            "medical_decisions": decisions,
            "sae_ids": sae_ids,
            "deviation_ids": deviation_ids,
            "consent_id": subject["consent_id"],
            "enrolled_at": subject["enrolled_at"],
        }

    def subject_provenance(self, actor: dict[str, Any], subject_id: str) -> dict[str, Any]:
        actor = self._actor(actor)
        with self._lock:
            subject = self._get(self.subjects, "受试者", subject_id)
            if subject["protocol_id"] is None:
                raise StateConflictError("受试者尚未入组，暂无研究溯源链")
            return self._provenance_chain(subject)

    # ----- 视图与盲态红action -------------------------------------------

    def get_subject(self, actor: dict[str, Any], subject_id: str) -> dict[str, Any]:
        actor = self._actor(actor)
        with self._lock:
            subject = self._snapshot(self._get(self.subjects, "受试者", subject_id))
            if actor["role"] == "盲态评价者":
                return self._blind_view(subject)
            return subject

    def list_subjects(self, actor: dict[str, Any]) -> list[dict[str, Any]]:
        actor = self._actor(actor)
        with self._lock:
            records = [self._snapshot(s) for s in self.subjects.values()]
            if actor["role"] == "盲态评价者":
                return [self._blind_view(s) for s in records]
            return records

    def _blind_view(self, subject: dict[str, Any]) -> dict[str, Any]:
        view = {k: subject.get(k) for k in BLIND_SAFE_SUBJECT_FIELDS}
        # 盲态角色可见去标识采集物引用，但看不到剂量/队列/治疗时间线
        view["artifact_refs"] = [
            {"artifact_id": a["artifact_id"], "artifact_type": a["artifact_type"],
             "ref": a["ref"], "checksum": a["checksum"], "captured_at": a["captured_at"]}
            for a in self.artifacts.values()
            if a["subject_id"] == subject["subject_id"]
        ]
        return view

    def list_cohorts(self, actor: dict[str, Any]) -> list[dict[str, Any]]:
        actor = self._actor(actor)
        if actor["role"] == "盲态评价者":
            raise PermissionDeniedError("盲态角色不得接触剂量队列信息")
        with self._lock:
            return [self._snapshot(c) for c in self.cohorts.values()]

    def subject_timeline(self, actor: dict[str, Any], subject_id: str) -> list[dict[str, Any]]:
        actor = self._actor(actor)
        with self._lock:
            self._get(self.subjects, "受试者", subject_id)
            if actor["role"] == "盲态评价者":
                raise PermissionDeniedError("盲态角色不得接触治疗时间线与队列信息")
            rows = [
                self._snapshot(a) for a in self.activities.values()
                if a["subject_id"] == subject_id
            ]
            rows.sort(key=lambda a: (a["actual_at"] or a["planned_at"]))
            return rows

    # ----- 导出（供监查/上报，不做权限收窄，调用方自行鉴权） -------------

    def export_subject_csv(self, actor: dict[str, Any]) -> str:
        """导出受试者状态宽表（不含任何自由文本 PII，仅受控字段）。"""
        actor = self._actor(actor)
        with self._lock:
            buffer = io.StringIO()
            writer = csv.writer(buffer)
            writer.writerow([
                "subject_id", "site_id", "status", "protocol_version",
                "cohort_id", "enrolled_at", "treatment_at",
                "window_start", "window_end", "evaluable", "withdrawn",
            ])
            for s in self.subjects.values():
                window = s.get("window") or {}
                writer.writerow([
                    s["subject_id"], s["site_id"], s["status"],
                    s["protocol_version"] or "", s["cohort_id"] or "",
                    s["enrolled_at"] or "", s["treatment_at"] or "",
                    window.get("start_at", ""), window.get("end_at", ""),
                    "" if s["evaluable"] is None else str(s["evaluable"]).lower(),
                    str(s["withdrawn"]).lower(),
                ])
            return buffer.getvalue()
