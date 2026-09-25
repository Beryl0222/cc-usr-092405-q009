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

# 方案修订（队列扩展阶段）
AMENDMENT_KINDS = ("常规修订", "紧急安全修订")
AMENDMENT_STATUSES = ("草拟", "待安全委员会批准", "已批准", "已驳回", "已撤销")
# 修订可声明的影响域：剂量 / 器械 / 观察窗口 / 安全规则
IMPACT_DOMAINS = ("剂量", "器械", "观察窗口", "安全规则")
# 紧急安全修订冻结后补审的最长期限（小时），提交时必须给出不超过该值的期限
EMERGENCY_REVIEW_DEADLINE_MAX_HOURS = 72
EMERGENCY_REVIEW_STATUSES = ("待补审", "已补审", "已逾期")
# 中心对修订的采用状态
SITE_ADOPTION_STATUSES = ("待采用", "已采用", "已拒绝")
# 逐受试者处置：继续 / 补充同意 / 重新排程 / 退出
SUBJECT_DISPOSITIONS = ("继续", "补充同意", "重新排程", "退出")
REQUIREMENT_ACTIONS = ("重新签署同意", "重新排程")
# 处置完成（要求闭环）后允许恢复研究操作的受试者状态
DISPOSITION_RESOLVED = ("继续", "退出")
# 处置过程中（要求尚未闭环）的受试者状态
DISPOSITION_PENDING = ("补充同意", "重新排程")

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
        # 方案修订（队列扩展阶段）
        self.amendments: dict[str, dict[str, Any]] = {}
        self.amendment_order: list[str] = []
        # amendment_id -> {site_id: adoption 记录}
        self.site_adoptions: dict[str, dict[str, dict[str, Any]]] = {}
        # (amendment_id, subject_id) -> disposition 记录
        self.subject_dispositions: dict[tuple[str, str], dict[str, Any]] = {}
        # 待办事项（只增，状态迁移）：todo_id -> 记录
        self.todos: dict[str, dict[str, Any]] = {}
        self.todo_order: list[str] = []

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
            self._amendment_gate(subject)
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
            # 方案修订（含紧急安全修订）冻结未闭环前，不得登记新的紧急偏离规避
            self._amendment_gate(subject)
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
        return self._schedule_activity_core(
            actor, subject_id=subject_id, kind=kind, planned_at=planned_at,
            activity_id=activity_id,
        )

    def _schedule_activity_core(
        self,
        actor: dict[str, Any],
        *,
        subject_id: str,
        kind: str,
        planned_at: Any,
        activity_id: Optional[str] = None,
        _amendment_bypass: bool = False,
    ) -> dict[str, Any]:
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
                self._treatment_gate(subject, at=planned, for_scheduling=True,
                                     _amendment_bypass=_amendment_bypass)
            else:
                self._emergency_review_gate(subject_id)
                if not _amendment_bypass:
                    self._amendment_gate(subject)
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
        check_emergency: bool = True, _amendment_bypass: bool = False,
    ) -> None:
        """治疗前阻断规则：错误方案/SAE/撤回/未分配队列一律阻止。

        执行紧急偏离的目标活动时由调用方传 check_emergency=False 自行豁免。
        修订处置中的"重新排程"由调用方传 _amendment_bypass=True 放行修订闸门
        （此时已在修订流程内、按新版本校验其余规则）。
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
        if not _amendment_bypass:
            self._amendment_gate(subject)

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
                # 方案修订冻结（尤其紧急安全修订）同样不能被受试者级紧急偏离覆盖
                self._amendment_gate(subject)
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
            else:
                # 非治疗类活动同样受修订闭环与紧急偏离冻结约束
                self._emergency_review_gate(subject["subject_id"])
                self._amendment_gate(subject)

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
                self._amendment_gate(subject)
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
            self._amendment_gate(subject)
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
            self._amendment_gate(subject)
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
            self._amendment_gate(subject)
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
        # 影响过该受试者的方案修订（含处置与快照治疗事实），支撑旧版本回溯
        amendments = []
        for aid in self.amendment_order:
            disp = self.subject_dispositions.get((aid, sid))
            if disp is None:
                continue
            amd = self.amendments[aid]
            row = next((r for r in (amd["impact_snapshot"] or {}).get("subjects", [])
                        if r["subject_id"] == sid), None)
            amendments.append({
                "amendment_id": aid,
                "kind": amd["kind"],
                "base_version": amd["base_version"],
                "new_version": amd["new_version"],
                "impact_domains": list(amd["impact_domains"]),
                "requires_reconsent": amd["requires_reconsent"],
                "status": amd["status"],
                "recommendation": disp["recommendation"],
                "decision": disp["decision"],
                "final_decision": disp.get("final_decision"),
                "disposition_status": disp["status"],
                "reconsent_id": disp.get("reconsent_id"),
                "reschedule_activity_ids": list(disp.get("reschedule_activity_ids", [])),
                "resolved_at": disp.get("resolved_at"),
                "treatment_facts_at_snapshot": None if row is None else row["treatment_facts"],
            })
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
            "amendments": amendments,
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

    # ----- 方案修订（队列扩展） ------------------------------------------

    def submit_amendment(
        self,
        actor: dict[str, Any],
        *,
        protocol_id: str,
        new_version: str,
        summary: str,
        impact_domains: list[str],
        requires_reconsent: bool,
        emergency: bool = False,
        reason: str = "",
        review_deadline_hours: Optional[int] = None,
        amendment_id: Optional[str] = None,
    ) -> dict[str, Any]:
        """提交方案修订。

        修订必须声明受影响的范围（剂量/器械/观察窗口/安全规则）以及是否需要
        重新知情同意。安全角色批准后才生成逐受试者影响快照。

        紧急安全修订（emergency=True）允许"先冻结再补审"：提交即对受影响
        在组受试者生效冻结，但必须给出紧急理由与补审期限（不超过
        EMERGENCY_REVIEW_DEADLINE_MAX_HOURS 小时），二者缺一不可。
        """
        actor = self._actor(actor)
        self._require_role(actor, "研究者", "试验协调员")
        new_version = str(new_version).strip()
        if not re.fullmatch(r"[A-Za-z0-9._-]+", new_version):
            raise ValidationError("方案版本号只允许字母数字及 . _ -")
        domains: list[str] = []
        for d in impact_domains or []:
            if d not in IMPACT_DOMAINS:
                raise ValidationError(f"未知影响域：{d}；允许：{'、'.join(IMPACT_DOMAINS)}")
            if d not in domains:
                domains.append(d)
        if not domains:
            raise ValidationError("修订必须声明至少一个受影响范围（剂量/器械/观察窗口/安全规则）")
        if not str(summary).strip():
            raise ValidationError("修订必须填写变更摘要")
        is_emergency = bool(emergency)
        if is_emergency:
            if not str(reason).strip():
                raise ValidationError("紧急安全修订必须写明紧急理由", )
            if review_deadline_hours is None:
                raise ValidationError("紧急安全修订必须给出补审期限")
            hours = int(review_deadline_hours)
            if hours <= 0 or hours > EMERGENCY_REVIEW_DEADLINE_MAX_HOURS:
                raise ValidationError(
                    f"补审期限必须为 1~{EMERGENCY_REVIEW_DEADLINE_MAX_HOURS} 小时的正整数"
                )
        elif review_deadline_hours is not None:
            raise ValidationError("仅紧急安全修订可设置补审期限")
        with self._lock:
            base = self._get(self.protocols, "方案", protocol_id)
            for proto in self.protocols.values():
                if proto["version"] == new_version:
                    raise StateConflictError(f"方案版本已存在：{new_version}",
                                             code="duplicate_protocol")
            # 新版本方案在批准时才创建；此处先防止两份在途修订抢占同一版本号
            for other_id in self.amendment_order:
                other = self.amendments[other_id]
                if (other["new_version"] == new_version
                        and other["status"] not in ("已驳回", "已撤销")):
                    raise StateConflictError(
                        f"已有在途修订 {other_id} 声明新版本 {new_version}",
                        code="duplicate_protocol")
            aid = amendment_id or _new_id("amd")
            if aid in self.amendments:
                raise StateConflictError(f"修订已存在：{aid}", code="duplicate_amendment")
            now = self._now()
            record = {
                "amendment_id": aid,
                "kind": "紧急安全修订" if is_emergency else "常规修订",
                "base_protocol_id": base["protocol_id"],
                "base_version": base["version"],
                "new_version": new_version,
                "summary": summary,
                "impact_domains": domains,
                "requires_reconsent": bool(requires_reconsent),
                "status": "待安全委员会批准",
                "submitted_by": actor["id"],
                "submitted_at": now.isoformat(timespec="seconds"),
                "review": None,
                "impact_snapshot": None,
                "snapshot_generated_at": None,
                "emergency": {
                    "active": is_emergency,
                    "reason": str(reason).strip(),
                    "review_deadline_hours": int(review_deadline_hours) if is_emergency else None,
                    "review_due_at": (
                        (now + timedelta(hours=hours)).isoformat(timespec="seconds")
                        if is_emergency else None
                    ),
                    "review_status": "待补审" if is_emergency else None,
                    "retro_review": None,
                    "froze_at": now.isoformat(timespec="seconds") if is_emergency else None,
                },
            }
            self.amendments[aid] = record
            self.amendment_order.append(aid)
            self.site_adoptions[aid] = {}
            self._audit_log(actor, "submit_amendment", "amendment", aid,
                            {"base_version": base["version"],
                             "new_version": new_version, "kind": record["kind"],
                             "impact_domains": domains,
                             "requires_reconsent": bool(requires_reconsent)})
            # 紧急安全修订：先冻结——立即生成影响快照、逐受试者处置与各中心待办，
            # 并冻结受影响在组受试者的后续研究操作，等待安全委员会补审。
            if is_emergency:
                self._generate_impact_snapshot(record, now)
                self._seed_adoptions_and_subjects(record, now, frozen=True)
            return self._snapshot(record)

    def review_amendment(
        self,
        actor: dict[str, Any],
        *,
        amendment_id: str,
        approved: bool,
        rationale: str,
        new_protocol_params: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """安全角色批准/驳回修订。批准后生成逐受试者影响快照并创建中心待办；
        紧急安全修订调用本接口完成"补审"。

        批准常规修订时应通过 new_protocol_params 提供新版本方案参数
        （observation_days / drug_to_light 等），系统据此创建已放行的新版本方案。
        """
        actor = self._actor(actor)
        self._require_role(actor, "安全委员会")
        if not str(rationale).strip():
            raise ValidationError("修订批准/驳回必须写明理由")
        with self._lock:
            record = self._get(self.amendments, "修订", amendment_id)
            if record["status"] not in ("待安全委员会批准",):
                raise StateConflictError(
                    f"修订状态为 {record['status']}，安全委员会只能复核待批准修订"
                )
            now = self._now()
            review = {
                "approved": bool(approved),
                "rationale": rationale,
                "reviewed_by": actor["id"],
                "at": now.isoformat(timespec="seconds"),
            }
            record["review"] = review
            if not approved:
                record["status"] = "已驳回"
                if record["emergency"]["active"]:
                    # 紧急修订被驳回：解除冻结，关闭派生待办/处置
                    self._lift_emergency_freeze(record, now)
                self._audit_log(actor, "review_amendment", "amendment", amendment_id,
                                {"approved": False})
                return self._snapshot(record)

            # 批准：常规修订此刻生成快照与待办；紧急修订补审即确认并解除冻结标记
            if record["kind"] == "常规修订":
                self._create_new_protocol(record, new_protocol_params or {}, now)
                self._generate_impact_snapshot(record, now)
                self._seed_adoptions_and_subjects(record, now, frozen=False)
            else:
                self._create_new_protocol(record, new_protocol_params or {}, now)
                em = record["emergency"]
                overdue = now > _parse_dt(em["review_due_at"])
                em["review_status"] = "已逾期" if overdue else "已补审"
                em["retro_review"] = review
                # 冻结期已提前采用的中心，补授新版本资质
                new_version = record["new_version"]
                for ad in self.site_adoptions.get(record["amendment_id"], {}).values():
                    site = self.sites.get(ad["site_id"])
                    if site is not None and new_version not in site["qualified_versions"]:
                        site["qualified_versions"].append(new_version)
                self._lift_emergency_freeze(record, now, approved=True)
            record["status"] = "已批准"
            self.decisions.append(
                {"scope": "amendment", "target_id": amendment_id,
                 "decision": "继续", **review}
            )
            self._audit_log(actor, "review_amendment", "amendment", amendment_id,
                            {"approved": True, "kind": record["kind"]})
            return self._snapshot(record)

    def _create_new_protocol(
        self, amendment: dict[str, Any], params: dict[str, Any], now: datetime
    ) -> dict[str, Any]:
        """按修订创建新版本方案记录（已批准修订直接为已放行状态）。"""
        for proto in self.protocols.values():
            if proto["version"] == amendment["new_version"]:
                return proto
        base = self.protocols[amendment["base_protocol_id"]]
        pid = _new_id("proto")
        observation_days = int(params.get("observation_days", base["observation_days"]))
        resect_days = int(params.get("resect_assessment_days",
                                     base["resect_assessment_days"]))
        d2l = params.get("drug_to_light") or {}
        record = {
            "protocol_id": pid,
            "version": amendment["new_version"],
            "based_on": base["protocol_id"],
            "status": "已放行",
            "observation_days": observation_days,
            "resect_assessment_days": resect_days,
            "drug_to_light": {
                "min_minutes": int(d2l.get("min_minutes",
                                           base["drug_to_light"]["min_minutes"])),
                "max_minutes": int(d2l.get("max_minutes",
                                           base["drug_to_light"]["max_minutes"])),
            },
            "notes": f"由修订 {amendment['amendment_id']} 自 {base['version']} 升级",
            "approval": {
                "decision": "继续",
                "rationale": amendment["review"]["rationale"],
                "committee_actor_id": amendment["review"]["reviewed_by"],
                "at": amendment["review"]["at"],
            },
            "created_at": now.isoformat(timespec="seconds"),
            "introduced_by_amendment": amendment["amendment_id"],
        }
        self.protocols[pid] = record
        self.protocol_order.append(pid)
        amendment["new_protocol_id"] = pid
        return record

    def _generate_impact_snapshot(
        self, amendment: dict[str, Any], now: datetime
    ) -> dict[str, Any]:
        """基于已经发生的治疗事实，逐受试者生成影响快照。

        快照在批准（或紧急冻结）时刻一次性确定，此后不再随状态变化，保证
        不同中心采用顺序、请求到达顺序都不会改变每名受试者的判定。
        """
        base_pid = amendment["base_protocol_id"]
        subjects = []
        for sid in sorted(self.subjects):
            s = self.subjects[sid]
            if s["protocol_id"] != base_pid:
                continue
            # 只影响仍在组（未撤回）且已入组者；撤回者由撤回规则优先处理，不入快照
            if s["status"] == "筛选中" or s["withdrawn"]:
                continue
            facts = self._treatment_facts(s)
            recommendation, reasons, reqs = self._recommend_disposition(
                amendment, s, facts
            )
            subjects.append({
                "subject_id": sid,
                "site_id": s["site_id"],
                "status_at_snapshot": s["status"],
                "consent_version_at_snapshot": (
                    self.consents.get(s["consent_id"] or {}, {}).get("consent_version")
                ),
                "treatment_facts": facts,
                "recommendation": recommendation,
                "recommendation_reasons": reasons,
                "requirements": reqs,
            })
        snapshot = {
            "amendment_id": amendment["amendment_id"],
            "base_protocol_id": base_pid,
            "base_version": amendment["base_version"],
            "new_version": amendment["new_version"],
            "generated_at": now.isoformat(timespec="seconds"),
            "impact_domains": list(amendment["impact_domains"]),
            "requires_reconsent": amendment["requires_reconsent"],
            "emergency_active": amendment["emergency"]["active"],
            "subjects": subjects,
        }
        amendment["impact_snapshot"] = snapshot
        amendment["snapshot_generated_at"] = snapshot["generated_at"]
        return snapshot

    def _treatment_facts(self, subject: dict[str, Any]) -> dict[str, Any]:
        """汇总受试者已经发生的治疗事实（注射/照光、剂量、器械、观察窗）。"""
        sid = subject["subject_id"]
        injections = [a for a in self.activities.values()
                      if a["subject_id"] == sid and a["kind"] == "注射"
                      and a["outcome"] == "按计划完成"]
        lights = [a for a in self.activities.values()
                  if a["subject_id"] == sid and a["kind"] == "激光照射"
                  and a["outcome"] == "按计划完成"]
        swaps = [a for a in self.activities.values()
                 if a["subject_id"] == sid and a["outcome"] == "器械更换"]
        return {
            "injection_completed": bool(injections),
            "light_completed": bool(lights),
            "injection_count": len(injections),
            "light_count": len(lights),
            "device_swap_count": len(swaps),
            "drug_lot_ids": sorted({a["lot_id"] for a in injections if a["lot_id"]}),
            "device_lot_ids": sorted({a["device_lot_id"] for a in lights
                                      if a["device_lot_id"]}),
            "last_treatment_at": max(
                [a["actual_at"] for a in injections + lights if a["actual_at"]],
                default=None,
            ),
            "window_open": subject.get("window") is not None,
            "window": self._snapshot(subject["window"]) if subject.get("window") else None,
            "in_observation": (
                subject.get("status") in ("观察中", "可评估")
                or subject.get("window") is not None
            ),
        }

    def _recommend_disposition(
        self,
        amendment: dict[str, Any],
        subject: dict[str, Any],
        facts: dict[str, Any],
    ) -> tuple[str, list[str], list[str]]:
        """根据已发生治疗事实给出处置建议与必须完成的要求。确定性，无外部状态。"""
        domains = amendment["impact_domains"]
        reasons: list[str] = []
        reqs: list[str] = []

        if facts["light_completed"]:
            # 照光已完成：治疗事实不可改变
            if "观察窗口" in domains and facts["window_open"]:
                recommendation = "退出"
                reasons.append("观察窗口规则已变更且受试者已完成照光、观察窗已开启，"
                               "无法按新窗口重算，建议退出研究随访")
                return recommendation, reasons, reqs
            recommendation = "继续"
            if "剂量" in domains:
                reasons.append("剂量规则变更，但实际给药与照光均已完成，治疗事实不可变更")
            if "器械" in domains:
                reasons.append("器械规则变更，但照光已完成，仅需沿用新安全规则随访")
            if "安全规则" in domains:
                reasons.append("安全规则变更，按新规则继续随访")
            if amendment["requires_reconsent"]:
                recommendation = "补充同意"
                reqs.append("重新签署同意")
                reasons.append("修订要求重新知情同意")
            else:
                reasons.append("无需重新同意，可继续")
            return recommendation, reasons, reqs

        if facts["injection_completed"] and not facts["light_completed"]:
            # 已给药未照光
            recommendation = "重新排程"
            reqs.append("重新排程")
            reasons.append("已完成药物注射但尚未照光，后续照光须按修订后方案重新排程")
            if "剂量" in domains:
                reasons.append("剂量规则变更影响待执行的照光剂量")
            if "器械" in domains or facts["device_swap_count"]:
                reasons.append("器械规则变更，重排时须核验合格器械批次")
            if amendment["requires_reconsent"]:
                recommendation = "补充同意"
                reqs.insert(0, "重新签署同意")
                reasons.append("修订要求重新知情同意")
            return recommendation, reasons, reqs

        # 尚未治疗
        recommendation = "继续"
        reasons.append("尚未发生治疗事实，按新版本继续即可")
        if amendment["requires_reconsent"]:
            recommendation = "补充同意"
            reqs.append("重新签署同意")
            reasons.append("修订要求重新知情同意")
        return recommendation, reasons, reqs

    def _seed_adoptions_and_subjects(
        self, amendment: dict[str, Any], now: datetime, *, frozen: bool
    ) -> None:
        """快照生成后：为每个涉及中心建立采用待办，为每名受试者建立处置待办。"""
        snapshot = amendment["impact_snapshot"]
        site_ids: list[str] = []
        for row in snapshot["subjects"]:
            if row["site_id"] not in site_ids:
                site_ids.append(row["site_id"])
        for site_id in site_ids:
            adoption = {
                "amendment_id": amendment["amendment_id"],
                "site_id": site_id,
                "status": "待采用",
                "adopted_at": None,
                "adopted_by": None,
                "note": "",
                "frozen_pending_adoption": frozen,
            }
            self.site_adoptions[amendment["amendment_id"]][site_id] = adoption
            self._add_todo(
                kind="中心采用修订", amendment_id=amendment["amendment_id"],
                site_id=site_id, subject_id=None,
                title=f"中心 {site_id} 需采用修订 {amendment['amendment_id']}"
                      f"（{amendment['base_version']} → {amendment['new_version']}）",
                created_at=now, emergency=frozen,
                requirement=None,
            )
        for row in snapshot["subjects"]:
            disp = {
                "amendment_id": amendment["amendment_id"],
                "subject_id": row["subject_id"],
                "site_id": row["site_id"],
                "recommendation": row["recommendation"],
                "decision": None,
                "requirements": list(row["requirements"]),
                "requirements_status": {r: "待完成" for r in row["requirements"]},
                "status": "冻结待处置" if frozen else "待处置",
                "resolved_at": None,
                "resolved_by": None,
                "frozen": frozen,
                "reconsent_id": None,
                "reschedule_activity_ids": [],
                "note": "",
            }
            self.subject_dispositions[(amendment["amendment_id"], row["subject_id"])] = disp
            self._add_todo(
                kind="受试者修订处置", amendment_id=amendment["amendment_id"],
                site_id=row["site_id"], subject_id=row["subject_id"],
                title=f"受试者 {row['subject_id']} 修订处置：建议{row['recommendation']}",
                created_at=now, emergency=frozen,
                requirement=("重新签署同意" if "重新签署同意" in row["requirements"]
                             else ("重新排程" if row["requirements"] else None)),
            )

    def _add_todo(
        self, *, kind: str, amendment_id: str, site_id: str,
        subject_id: Optional[str], title: str, created_at: datetime,
        emergency: bool, requirement: Optional[str],
    ) -> str:
        tid = _new_id("todo")
        record = {
            "todo_id": tid,
            "kind": kind,
            "amendment_id": amendment_id,
            "site_id": site_id,
            "subject_id": subject_id,
            "title": title,
            "status": "待处理",
            "requirement": requirement,
            "emergency": emergency,
            "created_at": created_at.isoformat(timespec="seconds"),
            "closed_at": None,
            "closed_by": None,
        }
        self.todos[tid] = record
        self.todo_order.append(tid)
        return tid

    def _close_todos(self, *, amendment_id: str, site_id: str,
                     subject_id: Optional[str], actor_id: str, at: datetime) -> None:
        for tid, t in self.todos.items():
            if t["amendment_id"] != amendment_id or t["site_id"] != site_id:
                continue
            if subject_id is not None and t["subject_id"] != subject_id:
                continue
            if t["status"] == "待处理":
                t["status"] = "已处理"
                t["closed_at"] = at.isoformat(timespec="seconds")
                t["closed_by"] = actor_id

    def _lift_emergency_freeze(
        self, amendment: dict[str, Any], now: datetime, *, approved: bool = False
    ) -> None:
        """紧急修订补审/驳回后的冻结收尾。

        补审批准：解除全局紧急冻结标志，但受试者在中心采用、要求闭环前仍按
        常规修订流程保持阻断；驳回：受试者处置一律作废，完全解除阻断。
        """
        for disp in self.subject_dispositions.values():
            if disp["amendment_id"] != amendment["amendment_id"]:
                continue
            if not approved:
                disp["frozen"] = False
                disp["status"] = "已撤销"
            else:
                disp["frozen"] = False
                if disp["status"] == "冻结待处置":
                    disp["status"] = "待处置"
        for adoption in self.site_adoptions.get(amendment["amendment_id"], {}).values():
            adoption["frozen_pending_adoption"] = False
        if not approved:
            # 驳回时关闭派生待办
            for t in self.todos.values():
                if t["amendment_id"] == amendment["amendment_id"] and t["status"] == "待处理":
                    t["status"] = "已撤销"
                    t["closed_at"] = now.isoformat(timespec="seconds")

    def adopt_amendment(
        self,
        actor: dict[str, Any],
        *,
        amendment_id: str,
        site_id: str,
        note: str = "",
    ) -> dict[str, Any]:
        """中心采用新版本修订。采用后该中心才可处置其名下受试者。

        紧急安全修订在补审前即处于冻结状态；中心采用不解除受试者层面的
        要求闭环阻断。未采用修订的中心不能按新版本开展操作。
        """
        actor = self._actor(actor)
        self._require_role(actor, "研究者", "试验协调员")
        with self._lock:
            amendment = self._get(self.amendments, "修订", amendment_id)
            adoptions = self.site_adoptions.get(amendment_id, {})
            adoption = adoptions.get(site_id)
            if adoption is None:
                raise NotFoundError(f"修订 {amendment_id} 不涉及中心 {site_id}")
            site = self._get(self.sites, "中心", site_id)
            if amendment["status"] != "已批准" and not (
                amendment["emergency"]["active"] and amendment["status"] == "待安全委员会批准"
            ):
                raise StateConflictError(
                    f"修订状态为 {amendment['status']}，尚不能被中心采用",
                    code="amendment_not_adoptable",
                )
            if adoption["status"] == "已采用":
                # 幂等：并发/重复确认直接返回既有记录，结果不随请求次数改变
                return self._snapshot(adoption)
            if adoption["status"] == "已拒绝":
                raise StateConflictError("该中心已拒绝采用此修订",
                                         code="site_rejected_amendment")
            now = self._now()
            adoption["status"] = "已采用"
            adoption["adopted_at"] = now.isoformat(timespec="seconds")
            adoption["adopted_by"] = actor["id"]
            adoption["note"] = note
            # 中心采用新版本即视为取得该版本资质授权
            new_pid = amendment.get("new_protocol_id")
            if new_pid is not None:
                new_version = amendment["new_version"]
                if new_version not in site["qualified_versions"]:
                    site["qualified_versions"].append(new_version)
            self._audit_log(actor, "adopt_amendment", "site", site_id,
                            {"amendment_id": amendment_id})
            self._close_todos(amendment_id=amendment_id, site_id=site_id,
                              subject_id=None, actor_id=actor["id"], at=now)
            return self._snapshot(adoption)

    def resolve_subject_amendment(
        self,
        actor: dict[str, Any],
        *,
        amendment_id: str,
        subject_id: str,
        decision: str,
        reconsent: Optional[dict[str, Any]] = None,
        reschedule: Optional[list[dict[str, Any]]] = None,
        note: str = "",
    ) -> dict[str, Any]:
        """逐受试者确认处置：继续 / 补充同意 / 重新排程 / 退出。

        - 中心必须已采用修订；
        - 选择"补充同意"必须随附重新签署的同意记录；选择"重新排程"必须随附
          重排后的活动；要求未闭环前该受试者的后续操作保持阻断；
        - 决策可收窄（补充同意/重新排程在补齐要求后以最终决策闭环），但
          重复确认幂等，结果不因并发请求顺序改变。
        """
        actor = self._actor(actor)
        self._require_role(actor, "研究者", "试验协调员")
        if decision not in SUBJECT_DISPOSITIONS:
            raise ValidationError(f"处置必须是：{'、'.join(SUBJECT_DISPOSITIONS)}")
        with self._lock:
            amendment = self._get(self.amendments, "修订", amendment_id)
            subject = self._get(self.subjects, "受试者", subject_id)
            disp = self.subject_dispositions.get((amendment_id, subject_id))
            if disp is None:
                raise NotFoundError("影响快照中不存在该受试者的修订处置记录")
            if disp["status"] in ("已完成", "已撤销"):
                # 幂等返回（含紧急修订被驳回后的撤销态）
                return self._snapshot(disp)
            adoption = self.site_adoptions[amendment_id].get(disp["site_id"])
            if adoption is None or adoption["status"] != "已采用":
                raise StateConflictError(
                    f"中心 {disp['site_id']} 尚未采用修订 {amendment_id}，"
                    "不能处置受试者",
                    code="site_amendment_not_adopted",
                )

            # 紧急安全修订：补审批准前只允许冻结，不允许逐受试者处置闭环
            if amendment["emergency"]["active"] and amendment["status"] != "已批准":
                raise StateConflictError(
                    "紧急安全修订尚待安全委员会补审，补审批准前不得处置受试者",
                    code="emergency_amendment_pending_review",
                )

            snapshot_row = self._snapshot_row(amendment, subject_id)
            now = self._now()

            # 撤回同意与未关闭 SAE 始终优先：禁止任何"继续治疗"类处置
            if subject["withdrawn"]:
                if decision != "退出":
                    raise StateConflictError(
                        "受试者已撤回同意，修订处置只能为退出（安全记录依规保留）",
                        code="subject_withdrawn",
                    )
                self._close_disposition(disp, decision, actor, now, note)
                return self._snapshot(disp)
            if self._open_sae(subject_id) is not None:
                raise StateConflictError(
                    "存在未关闭（未复核）的严重不良事件，须先经安全委员会复核，"
                    "再进行修订处置",
                    code="sae_hold",
                )

            recommendation = snapshot_row["recommendation"]
            # 决策不得比快照建议更"激进"：照光已完成者不可重新排程，
            # 已给药未照光者不可跳过重新排程直接继续（除非补充同意且仍重排）
            self._validate_disposition_decision(amendment, snapshot_row, decision)

            # 处理重新签署同意
            if reconsent is not None:
                if "重新签署同意" not in disp["requirements"]:
                    raise ValidationError("该受试者的修订处置不要求重新签署同意")
                consent = self._ingest_reconsent(actor, subject, amendment, reconsent)
                disp["reconsent_id"] = consent["consent_id"]
                disp["requirements_status"]["重新签署同意"] = "已完成"

            # 处理重新排程
            if reschedule is not None:
                if "重新排程" not in disp["requirements"]:
                    raise ValidationError("该受试者的修订处置不要求重新排程")
                ids = self._ingest_reschedule(actor, subject, amendment, reschedule)
                disp["reschedule_activity_ids"] = ids
                disp["requirements_status"]["重新排程"] = "已完成"

            disp["decision"] = decision
            disp["note"] = note

            pending = [r for r, st in disp["requirements_status"].items()
                       if st != "已完成"]
            if decision in DISPOSITION_PENDING and pending:
                disp["status"] = "待完成要求"
                self._audit_log(actor, "resolve_subject_amendment", "subject",
                                subject_id, {"amendment_id": amendment_id,
                                             "decision": decision,
                                             "pending_requirements": pending})
                return self._snapshot(disp)

            # 要求闭环（或无要求）：完成处置
            if decision in DISPOSITION_PENDING and not pending:
                # 补充同意 / 重新排程完成后，受试者回归新版本继续随访
                final_decision = "继续"
            else:
                final_decision = decision
            self._close_disposition(disp, final_decision, actor, now, note,
                                    chosen=decision)
            if final_decision == "继续" and not subject["withdrawn"]:
                # 将受试者绑定到新版本方案（队列归属等治疗事实保持不变）
                new_pid = amendment.get("new_protocol_id")
                if new_pid:
                    subject["protocol_id"] = new_pid
                    subject["protocol_version"] = amendment["new_version"]
            return self._snapshot(disp)

    def _ingest_reconsent(
        self, actor: dict[str, Any], subject: dict[str, Any],
        amendment: dict[str, Any], payload: dict[str, Any],
    ) -> dict[str, Any]:
        if subject["withdrawn"]:
            raise StateConflictError("受试者已撤回，不能登记新同意",
                                     code="subject_withdrawn")
        new_pid = amendment.get("new_protocol_id")
        protocol_version = amendment["new_version"]
        if new_pid is None:
            # 紧急冻结先于新版本方案创建：按版本号反查应失败，故此处仅在补审后允许
            raise StateConflictError("新版本方案尚未建立，不能登记新同意",
                                     code="amendment_not_adoptable")
        consent = self.record_consent(
            actor,
            subject_id=subject["subject_id"],
            protocol_version=protocol_version,
            signed_at=payload["signed_at"],
            consent_version=payload["consent_version"],
            document_ref=payload["document_ref"],
            document_checksum=payload["document_checksum"],
            consent_id=payload.get("consent_id"),
        )
        return consent

    def _ingest_reschedule(
        self, actor: dict[str, Any], subject: dict[str, Any],
        amendment: dict[str, Any], items: list[dict[str, Any]],
    ) -> list[str]:
        if not items:
            raise ValidationError("重新排程必须提供至少一个活动")
        new_pid = amendment.get("new_protocol_id")
        if new_pid is None:
            raise StateConflictError("新版本方案尚未建立，不能重新排程",
                                     code="amendment_not_adoptable")
        old_pid = subject["protocol_id"]
        ids: list[str] = []
        # 处置期间受试者仍绑定旧版本；仅在内部排程时临时指向新版本以过闸，
        # 排程后立即恢复，待处置闭环再正式改绑，避免绕过修订阻断。
        subject["protocol_id"] = new_pid
        subject["protocol_version"] = amendment["new_version"]
        try:
            for item in items:
                kind = item["kind"]
                if kind not in VISIT_KINDS:
                    raise ValidationError(f"活动类型必须是：{'、'.join(VISIT_KINDS)}")
                act = self._schedule_activity_core(
                    actor, subject_id=subject["subject_id"], kind=kind,
                    planned_at=item["planned_at"], activity_id=item.get("activity_id"),
                    _amendment_bypass=True,
                )
                ids.append(act["activity_id"])
        finally:
            subject["protocol_id"] = old_pid
            subject["protocol_version"] = self.protocols[old_pid]["version"]
        return ids

    def _validate_disposition_decision(
        self, amendment: dict[str, Any], row: dict[str, Any], decision: str
    ) -> None:
        rec = row["recommendation"]
        facts = row["treatment_facts"]
        if decision == "继续":
            if "重新排程" in row["requirements"]:
                raise StateConflictError(
                    "该受试者已给药未照光，必须先按新版本重新排程，不能直接继续",
                    code="reschedule_required",
                )
            if "重新签署同意" in row["requirements"]:
                raise StateConflictError(
                    "修订要求重新知情同意，必须先补充同意，不能直接继续",
                    code="reconsent_required",
                )
        if decision == "重新排程":
            if facts["light_completed"]:
                raise StateConflictError(
                    "受试者已完成照光，治疗事实不可改变，不能重新排程",
                    code="treatment_fact_locked",
                )
        if decision == "补充同意" and "重新签署同意" not in row["requirements"]:
            raise ValidationError("该修订不要求重新签署同意，无需补充同意")
        if decision == "退出":
            return

    def _close_disposition(
        self, disp: dict[str, Any], final_decision: str,
        actor: dict[str, Any], now: datetime, note: str, *, chosen: Optional[str] = None
    ) -> None:
        disp["status"] = "已完成"
        disp["resolved_at"] = now.isoformat(timespec="seconds")
        disp["resolved_by"] = actor["id"]
        disp["final_decision"] = final_decision
        disp["decision"] = chosen or final_decision
        if note:
            disp["note"] = note
        if final_decision == "退出":
            subject = self.subjects[disp["subject_id"]]
            # 退出研究：停止新增研究用途，既有与安全记录保留
            if not subject["withdrawn"]:
                subject["withdrawn"] = True
                subject["withdrawn_at"] = now.isoformat(timespec="seconds")
                subject["research_use_blocked_after"] = now.isoformat(timespec="seconds")
                subject["status"] = "已撤回"
        self._close_todos(amendment_id=disp["amendment_id"], site_id=disp["site_id"],
                          subject_id=disp["subject_id"], actor_id=actor["id"], at=now)
        self._audit_log(actor, "resolve_subject_amendment", "subject",
                        disp["subject_id"],
                        {"amendment_id": disp["amendment_id"],
                         "final_decision": final_decision})

    def _snapshot_row(self, amendment: dict[str, Any], subject_id: str) -> dict[str, Any]:
        for row in amendment["impact_snapshot"]["subjects"]:
            if row["subject_id"] == subject_id:
                return row
        raise NotFoundError("影响快照中不存在该受试者")

    # ----- 修订阻断闸门 --------------------------------------------------

    def _active_amendment_block(self, subject: dict[str, Any]) -> Optional[dict[str, Any]]:
        """返回当前阻断该受试者研究操作的未闭环修订处置（最高优先级一条）。

        优先级：紧急安全修订冻结 > 常规修订待处置；同类中较新的修订优先。
        撤回/SAE 由各业务闸门先行处理，始终优先于修订阻断。
        """
        sid = subject["subject_id"]
        best: Optional[dict[str, Any]] = None
        for aid in reversed(self.amendment_order):
            amendment = self.amendments[aid]
            if amendment["status"] == "已驳回" or amendment["status"] == "已撤销":
                continue
            disp = self.subject_dispositions.get((aid, sid))
            if disp is None or disp["status"] in ("已完成", "已撤销"):
                continue
            if disp["frozen"]:
                return {"amendment": amendment, "disposition": disp, "emergency": True}
            if best is None:
                best = {"amendment": amendment, "disposition": disp, "emergency": False}
        return best

    def _amendment_gate(self, subject: dict[str, Any]) -> None:
        """研究操作（排程/执行/采集/结局）的修订阻断校验。"""
        block = self._active_amendment_block(subject)
        if block is None:
            return
        amendment = block["amendment"]
        disp = block["disposition"]
        if block["emergency"]:
            raise StateConflictError(
                f"紧急安全修订 {amendment['amendment_id']} 已冻结该受试者，"
                "须等待安全委员会补审并完成修订处置",
                code="emergency_amendment_freeze",
            )
        pending = [r for r, st in disp["requirements_status"].items()
                   if st != "已完成"]
        req_text = "、".join(pending) if pending else "中心采用与受试者处置"
        raise StateConflictError(
            f"方案修订 {amendment['amendment_id']}（{amendment['base_version']} → "
            f"{amendment['new_version']}）尚未闭环：{req_text}；"
            "完成前阻断对应研究操作",
            code="amendment_requirements_open",
        )

    def emergency_amendment_overdue(self, amendment_id: str) -> dict[str, Any]:
        """推进紧急修订期限：超过补审期限仍未补审则标记逾期（供定时任务/查询调用）。"""
        with self._lock:
            amendment = self._get(self.amendments, "修订", amendment_id)
            em = amendment["emergency"]
            if not em["active"]:
                raise StateConflictError("该修订不是紧急安全修订")
            if em["retro_review"] is None and self._now() > _parse_dt(em["review_due_at"]):
                em["review_status"] = "已逾期"
            return self._snapshot(amendment)

    # ----- 修订视图与待办 -----------------------------------------------

    def list_amendments(self, actor: dict[str, Any]) -> list[dict[str, Any]]:
        actor = self._actor(actor)
        if actor["role"] == "盲态评价者":
            raise PermissionDeniedError("盲态角色不得接触方案修订（含剂量/治疗阶段信息）")
        with self._lock:
            return [self._snapshot(self.amendments[aid]) for aid in self.amendment_order]

    def get_amendment(self, actor: dict[str, Any], amendment_id: str) -> dict[str, Any]:
        actor = self._actor(actor)
        if actor["role"] == "盲态评价者":
            raise PermissionDeniedError("盲态角色不得接触方案修订（含剂量/治疗阶段信息）")
        with self._lock:
            return self._snapshot(self._get(self.amendments, "修订", amendment_id))

    def impact_snapshot(self, actor: dict[str, Any], amendment_id: str) -> dict[str, Any]:
        actor = self._actor(actor)
        if actor["role"] == "盲态评价者":
            raise PermissionDeniedError("盲态角色不得接触逐受试者影响快照")
        with self._lock:
            amendment = self._get(self.amendments, "修订", amendment_id)
            if amendment["impact_snapshot"] is None:
                raise StateConflictError("修订尚未经安全角色批准，影响快照未生成")
            return self._snapshot(amendment["impact_snapshot"])

    def pending_todos(
        self, actor: dict[str, Any], *, site_id: Optional[str] = None,
        status: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        """各中心通过接口领取自己的待办（中心采用 + 受试者处置）。"""
        actor = self._actor(actor)
        if actor["role"] == "盲态评价者":
            raise PermissionDeniedError("盲态角色不得接触修订待办（含治疗阶段信息）")
        with self._lock:
            rows = []
            for tid in self.todo_order:
                t = self.todos[tid]
                if site_id and t["site_id"] != site_id:
                    continue
                if status and t["status"] != status:
                    continue
                rows.append(self._snapshot(t))
            return rows

    def subject_available_actions(
        self, actor: dict[str, Any], subject_id: str
    ) -> dict[str, Any]:
        """查询受试者当前可执行/被阻断的动作（结果只取决于当前事实状态，
        不取决于请求到达顺序）。盲态角色只能看到收窄后的阻断状态，
        看不到剂量/队列/治疗时间线。"""
        actor = self._actor(actor)
        with self._lock:
            subject = self._get(self.subjects, "受试者", subject_id)
            blocked: list[dict[str, Any]] = []
            allowed: list[str] = []

            # 最高优先级：撤回
            if subject["withdrawn"]:
                blocked.append({"code": "subject_withdrawn",
                                "message": "受试者已撤回，停止新增研究用途；安全记录保留",
                                "blocks": ["schedule", "perform", "artifact", "outcome",
                                           "enroll", "amendment_continue"]})
            # 未关闭 SAE
            open_sae = self._open_sae(subject_id)
            if open_sae:
                blocked.append({"code": "sae_hold",
                                "message": f"未复核 SAE {open_sae['sae_id']}，治疗冻结",
                                "blocks": ["schedule_treatment", "perform_treatment"]})

            # 修订阻断
            amd_block = None if subject["withdrawn"] else self._active_amendment_block(subject)
            if amd_block is not None:
                amendment = amd_block["amendment"]
                disp = amd_block["disposition"]
                pending = [r for r, st in disp["requirements_status"].items()
                           if st != "已完成"]
                blocked.append({
                    "code": ("emergency_amendment_freeze" if amd_block["emergency"]
                             else "amendment_requirements_open"),
                    "amendment_id": amendment["amendment_id"],
                    "base_version": amendment["base_version"],
                    "new_version": amendment["new_version"],
                    "recommendation": disp["recommendation"],
                    "pending_requirements": pending,
                    "site_adoption_required": (
                        self.site_adoptions[amendment["amendment_id"]]
                        .get(disp["site_id"], {}).get("status") != "已采用"
                    ),
                    "blocks": ["schedule", "perform", "artifact", "outcome"],
                })

            # 常规可执行动作（依据当前事实状态）；存在任何阻断时清空，
            # 撤回时仅保留只读与安全报告；具体阻断原因见 blocked。
            allowed: list[str] = ["view_subject", "report_sae"]
            if not subject["withdrawn"]:
                if subject["status"] == "筛选中":
                    allowed.extend(["consent", "screen", "enroll"])
                if subject["status"] in ("已入组", "治疗中"):
                    allowed.append("assign_cohort")
                if subject["cohort_id"] and subject["status"] in ("已入组", "治疗中"):
                    allowed.extend(["schedule_treatment", "perform_treatment"])
                if subject.get("window"):
                    allowed.extend(["schedule_visit", "register_artifact",
                                    "record_outcome", "set_evaluability"])
            if blocked:
                allowed = [a for a in allowed if a in ("view_subject", "report_sae")]

            payload = {
                "subject_id": subject_id,
                "site_id": subject["site_id"],
                "status": subject["status"],
                "withdrawn": subject["withdrawn"],
                "allowed_actions": allowed,
                "blocked": blocked,
                "has_open_block": bool(blocked),
            }
            if actor["role"] == "盲态评价者":
                # 盲态收窄：不返回队列/剂量相关动作，仅保留状态与修订阻断事实
                payload["allowed_actions"] = [
                    a for a in payload["allowed_actions"]
                    if a in ("view_subject", "register_artifact", "record_outcome")
                ]
                for b in blocked:
                    b.pop("blocks", None)
            return payload

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
