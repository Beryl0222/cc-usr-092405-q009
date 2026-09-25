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

# 修订可声明的影响面（剂量/器械/观察窗口/安全规则）
AMENDMENT_IMPACT_DOMAINS = ("剂量", "器械", "观察窗口", "安全规则")
# 修订单状态：待复核（普通修订不产生冻结）/冻结生效中（紧急修订先冻结）/已批准/已驳回
AMENDMENT_STATUSES = ("待复核", "冻结生效中", "已批准", "已驳回")
# 中心采用状态
ADOPTION_STATUSES = ("待采用", "已采用")
# 逐受试者待办处置：继续 / 补充同意 / 重新排程 / 退出
AMENDMENT_RESOLUTIONS = ("继续", "补充同意", "重新排程", "退出")
# 待办状态：待处理 / 已完成（含各类处置的关闭留痕）/ 已失效（受试者撤回等优先事件）
TODO_STATUSES = ("待处理", "已完成", "已失效")

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

# 盲态评价者可见的修订待办字段：只能看到“有修订待办/是否阻断/期限”，
# 看不到剂量、器械、安全规则等修订实质内容
BLIND_SAFE_TODO_FIELDS = (
    "todo_id",
    "amendment_id",
    "subject_id",
    "site_id",
    "status",
    "resolution",
    "due_at",
    "overdue",
    "created_at",
    "resolved_at",
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

        # 方案修订（队列扩展）：修订本体、中心采用、逐受试者影响待办
        self.amendments: dict[str, dict[str, Any]] = {}
        self.amendment_order: list[str] = []
        self.adoptions: dict[tuple[str, str], dict[str, Any]] = {}
        self.amendment_todos: dict[str, dict[str, Any]] = {}
        self.amendment_todo_order: list[str] = []

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

    # ----- 方案修订（队列扩展） -----------------------------------------

    def submit_amendment(
        self,
        actor: dict[str, Any],
        *,
        protocol_id: str,
        new_version: str,
        impact: dict[str, dict[str, Any]],
        rationale: str,
        emergency: bool = False,
        review_due_at: Any = None,
        site_action_due_at: Any = None,
        amendment_id: Optional[str] = None,
    ) -> dict[str, Any]:
        """提交方案修订。

        impact 的键限定为 剂量/器械/观察窗口/安全规则 四个影响面，值为该影响面的
        具体声明（如剂量面可带 cohorts 选择器，仅列出的队列受影响）。
        普通修订进入“待复核”，不冻结任何操作；紧急安全修订立即冻结该方案下全部
        受试者的研究操作（“先冻结再补审”），但必须给出理由与补审期限。
        site_action_due_at 为可选的中心处置期限：中心采用后逐人待办的逾期标记据此
        计算；与紧急修订的补审期限相互独立。
        """
        actor = self._actor(actor)
        self._require_role(actor, "研究者", "试验协调员")
        if not str(rationale).strip():
            raise ValidationError("修订提交必须写明理由")
        new_version = str(new_version).strip()
        if not re.fullmatch(r"[A-Za-z0-9._-]+", new_version):
            raise ValidationError("新版本号只允许字母数字及 . _ -")
        impact_norm = self._normalize_impact(impact)
        with self._lock:
            proto = self._get(self.protocols, "方案", protocol_id)
            if proto["status"] != "已放行":
                raise StateConflictError(
                    "仅可对已放行方案提交修订（队列扩展阶段）",
                    code="protocol_not_approved",
                )
            for p in self.protocols.values():
                if p["version"] == new_version:
                    raise StateConflictError(f"方案版本已存在：{new_version}",
                                             code="duplicate_protocol")
            for amd in self.amendments.values():
                if amd["new_version"] == new_version:
                    raise StateConflictError(f"新版本号已被修订占用：{new_version}",
                                             code="duplicate_amendment_version")
            due_iso: Optional[str] = None
            if emergency:
                if review_due_at is None:
                    raise ValidationError("紧急安全修订必须给出补审期限 review_due_at")
                due = _parse_dt(review_due_at)
                if due <= self._now():
                    raise ValidationError("补审期限必须晚于当前时间")
                due_iso = due.isoformat(timespec="seconds")
            action_due_iso: Optional[str] = None
            if site_action_due_at is not None:
                action_due = _parse_dt(site_action_due_at)
                if action_due <= self._now():
                    raise ValidationError("中心处置期限必须晚于当前时间")
                action_due_iso = action_due.isoformat(timespec="seconds")
            aid = amendment_id or _new_id("amd")
            if aid in self.amendments:
                raise StateConflictError(f"修订已存在：{aid}", code="duplicate_amendment")
            record = {
                "amendment_id": aid,
                "protocol_id": protocol_id,
                "base_version": proto["version"],
                "new_version": new_version,
                "impact": impact_norm,
                "rationale": rationale,
                "emergency": bool(emergency),
                "review_due_at": due_iso,
                "site_action_due_at": action_due_iso,
                "status": "冻结生效中" if emergency else "待复核",
                "submitted_at": self._now().isoformat(timespec="seconds"),
                "submitted_by": actor["id"],
                "review": None,
                "new_protocol_id": None,
                "snapshots": [],
            }
            self.amendments[aid] = record
            self.amendment_order.append(aid)
            self._audit_log(actor, "submit_amendment", "amendment", aid,
                            {"protocol_id": protocol_id, "new_version": new_version,
                             "impact_domains": list(impact_norm),
                             "emergency": bool(emergency),
                             "review_due_at": due_iso,
                             "site_action_due_at": action_due_iso})
            return self._amendment_view(record)

    @staticmethod
    def _normalize_impact(impact: Any) -> dict[str, dict[str, Any]]:
        if not isinstance(impact, dict) or not impact:
            raise ValidationError("修订必须声明至少一个影响面：剂量/器械/观察窗口/安全规则")
        norm: dict[str, dict[str, Any]] = {}
        for domain, detail in impact.items():
            if domain not in AMENDMENT_IMPACT_DOMAINS:
                raise ValidationError(
                    f"未知影响面：{domain}；允许：{'、'.join(AMENDMENT_IMPACT_DOMAINS)}"
                )
            if not isinstance(detail, dict) or not detail:
                raise ValidationError(f"影响面 {domain} 必须给出非空声明")
            norm[domain] = copy.deepcopy(detail)
        return norm

    def review_amendment(
        self,
        actor: dict[str, Any],
        amendment_id: str,
        *,
        decision: str,
        rationale: str,
    ) -> dict[str, Any]:
        """安全委员会复核修订。decision 为 批准/已驳回。

        批准时生成逐受试者影响快照（事实与判定在同一把锁内固化，不受请求顺序影响）。
        紧急修订逾期补审仍被允许（fail-safe：冻结在复核前绝不自动解除），但留痕逾期。
        """
        actor = self._actor(actor)
        self._require_role(actor, "安全委员会")
        if decision not in ("批准", "驳回"):
            raise ValidationError("复核结论必须是：批准、驳回")
        if not str(rationale).strip():
            raise ValidationError("复核必须写明理由")
        with self._lock:
            record = self._get(self.amendments, "修订", amendment_id)
            if record["status"] in ("已批准", "已驳回"):
                raise StateConflictError(f"修订已完成复核：{record['status']}")
            now = self._now()
            ratified_late = (
                record["emergency"]
                and record["review_due_at"] is not None
                and now > _parse_dt(record["review_due_at"])
            )
            review = {
                "decision": decision,
                "rationale": rationale,
                "reviewed_by": actor["id"],
                "at": now.isoformat(timespec="seconds"),
                "ratified_late": ratified_late,
            }
            record["review"] = review
            if decision == "驳回":
                record["status"] = "已驳回"
                self._audit_log(actor, "review_amendment", "amendment", amendment_id,
                                {"decision": "驳回", "ratified_late": ratified_late})
                return self._amendment_view(record)
            record["status"] = "已批准"
            new_pid = self._create_amendment_protocol(record)
            record["new_protocol_id"] = new_pid
            record["snapshots"] = self._build_amendment_snapshots(record, now)
            self.decisions.append(
                {"scope": "amendment", "target_id": amendment_id, **review}
            )
            self._audit_log(actor, "review_amendment", "amendment", amendment_id,
                            {"decision": "批准",
                             "snapshot_subjects": len(record["snapshots"]),
                             "ratified_late": ratified_late})
            return self._amendment_view(record)

    def _create_amendment_protocol(self, amendment: dict[str, Any]) -> str:
        """修订批准即放行新版本：继承基线方案参数，链接修订来源与放行决议。"""
        base = self.protocols[amendment["protocol_id"]]
        pid = _new_id("proto")
        record = {
            "protocol_id": pid,
            "version": amendment["new_version"],
            "based_on": base["protocol_id"],
            "status": "已放行",
            "observation_days": base["observation_days"],
            "resect_assessment_days": base["resect_assessment_days"],
            "drug_to_light": copy.deepcopy(base["drug_to_light"]),
            "notes": f"由修订 {amendment['amendment_id']} 引入",
            "approval": {
                "decision": "继续",
                "rationale": amendment["review"]["rationale"],
                "committee_actor_id": amendment["review"]["reviewed_by"],
                "at": amendment["review"]["at"],
                "via_amendment_id": amendment["amendment_id"],
                "ratified_late": amendment["review"]["ratified_late"],
            },
            "source_amendment_id": amendment["amendment_id"],
            "created_at": self._now().isoformat(timespec="seconds"),
        }
        self.protocols[pid] = record
        self.protocol_order.append(pid)
        return pid

    def _build_amendment_snapshots(
        self, amendment: dict[str, Any], now: datetime
    ) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for sid in sorted(self.subjects):
            subject = self.subjects[sid]
            if subject["protocol_id"] != amendment["protocol_id"]:
                continue
            facts = self._treatment_facts(subject)
            decision = None if subject["withdrawn"] else self._decision_for(amendment, subject, facts)
            rows.append({
                "subject_id": sid,
                "site_id": subject["site_id"],
                "status_at_review": subject["status"],
                "withdrawn": bool(subject["withdrawn"]),
                "facts": facts,
                "decision": decision,
                "generated_at": now.isoformat(timespec="seconds"),
            })
        return rows

    def _treatment_facts(self, subject: dict[str, Any]) -> dict[str, Any]:
        """已发生的治疗事实：修订判定只依赖这些事实，保证顺序无关。"""
        sid = subject["subject_id"]
        injections: list[str] = []
        lights_done: list[str] = []
        lights_open: list[str] = []
        for act in self.activities.values():
            if act["subject_id"] != sid:
                continue
            if act["kind"] == "注射" and act["outcome"] == "按计划完成":
                injections.append(act["activity_id"])
            elif act["kind"] == "激光照射":
                if act["outcome"] == "按计划完成":
                    lights_done.append(act["activity_id"])
                elif act["status"] == "已排程":
                    lights_open.append(act["activity_id"])
        return {
            "status": subject["status"],
            "cohort_id": subject["cohort_id"],
            "injections_completed": sorted(injections),
            "lights_completed": sorted(lights_done),
            "lights_scheduled_open": sorted(lights_open),
            "window_open": subject["window"] is not None,
            "open_sae_id": (self._open_sae(sid) or {}).get("sae_id"),
            "withdrawn": bool(subject["withdrawn"]),
        }

    def _impact_applies_to_subject(
        self, amendment: dict[str, Any], domain: str,
        subject: dict[str, Any], facts: dict[str, Any],
    ) -> bool:
        detail = amendment["impact"].get(domain)
        if detail is None:
            return False
        if domain == "剂量":
            cohorts = detail.get("cohorts")
            if cohorts and subject.get("cohort_id") not in cohorts:
                return False
        return True

    def _decision_for(
        self, amendment: dict[str, Any], subject: dict[str, Any],
        facts: dict[str, Any],
    ) -> str:
        """逐受试者判定：继续/补充同意/重新排程/退出。

        纯函数：同样的影响面声明与治疗事实必定得到同样结论。
        """
        # 剂量面优先：已照光者治疗事实全部完成，按原剂量继续随访；
        # 已给药未照光者不能跨剂量（退出修订，按原版本随访）；未给药者补签同意。
        if self._impact_applies_to_subject(amendment, "剂量", subject, facts):
            if facts["lights_completed"]:
                return "继续"
            return "退出" if facts["injections_completed"] else "补充同意"
        # 安全规则面：新安全信息须重新知情同意
        if self._impact_applies_to_subject(amendment, "安全规则", subject, facts):
            return "补充同意"
        # 器械面：待照光活动重排到新器械；已照光不受影响；尚未开始者补充同意
        if self._impact_applies_to_subject(amendment, "器械", subject, facts):
            if facts["lights_completed"]:
                return "继续"
            if facts["lights_scheduled_open"] or facts["injections_completed"]:
                return "重新排程"
            return "补充同意"
        # 观察窗口面：窗已开启按原窗继续；有待执行活动则重排；否则补充同意
        if self._impact_applies_to_subject(amendment, "观察窗口", subject, facts):
            if facts["window_open"]:
                return "继续"
            return "补充同意"
        return "继续"

    def adopt_amendment_at_site(
        self, actor: dict[str, Any], *, amendment_id: str, site_id: str
    ) -> dict[str, Any]:
        """中心采用新版本：按该中心受试者已发生的治疗事实实例化逐人待办。

        幂等：重复采用返回同一采用记录与同一批待办，并发/乱序请求结果一致。
        """
        actor = self._actor(actor)
        self._require_role(actor, "研究者", "试验协调员")
        with self._lock:
            amendment = self._get(self.amendments, "修订", amendment_id)
            if amendment["status"] != "已批准":
                raise StateConflictError(
                    "修订尚未获安全委员会批准，中心不得采用",
                    code="amendment_not_approved",
                )
            self._get(self.sites, "中心", site_id)
            key = (amendment_id, site_id)
            existing = self.adoptions.get(key)
            if existing is not None:
                return self._snapshot(existing)
            # 采用即取得新版本资质（中心资质仍须在有效期内且未被暂停/终止）
            site = self.sites[site_id]
            if site["status"] != "已批准":
                raise StateConflictError(
                    f"中心 {site_id} 状态为 {site['status']}，不得采用新版本",
                    code="site_not_qualified",
                )
            if _parse_dt(site["credentials_expire_at"]) < self._now():
                raise StateConflictError(
                    f"中心 {site_id} 资质已到期，不得采用新版本",
                    code="site_credentials_expired",
                )
            if amendment["new_version"] not in site["qualified_versions"]:
                site["qualified_versions"].append(amendment["new_version"])
            now = self._now()
            todo_ids: list[str] = []
            snapshot_rows = {row["subject_id"]: row for row in amendment["snapshots"]}
            for sid in sorted(self.subjects):
                subject = self.subjects[sid]
                if subject["site_id"] != site_id:
                    continue
                if subject["protocol_id"] != amendment["protocol_id"]:
                    continue
                if subject["withdrawn"]:
                    continue  # 撤回始终优先：不产生待办
                facts = self._treatment_facts(subject)
                required = self._decision_for(amendment, subject, facts)
                approved_row = snapshot_rows.get(sid)
                approved_decision = None if approved_row is None else approved_row["decision"]
                tid = f"{amendment_id}:{site_id}:{sid}"
                todo = {
                    "todo_id": tid,
                    "amendment_id": amendment_id,
                    "protocol_id": amendment["protocol_id"],
                    "site_id": site_id,
                    "subject_id": sid,
                    "status": "待处理",
                    "required_resolution": required,
                    "allowed_resolutions": [required] if required == "退出" else [required, "退出"],
                    "approved_decision": approved_decision,
                    # 批准到采用之间治疗事实若已推进，判定漂移在此留痕，
                    # 处置仍以采用时事实为准（顺序无关、事实驱动）
                    "decision_drift": (
                        approved_decision is not None and approved_decision != required
                    ),
                    "in_approved_snapshot": approved_row is not None,
                    "decision_facts": facts,
                    # 逐人处置期限独立于紧急修订的补审期限
                    "due_at": amendment.get("site_action_due_at"),
                    "resolution": None,
                    "created_at": now.isoformat(timespec="seconds"),
                    "created_by": actor["id"],
                    "resolved_at": None,
                }
                self.amendment_todos[tid] = todo
                self.amendment_todo_order.append(tid)
                todo_ids.append(tid)
            record = {
                "amendment_id": amendment_id,
                "site_id": site_id,
                "status": "已采用",
                "adopted_at": now.isoformat(timespec="seconds"),
                "adopted_by": actor["id"],
                "todo_ids": todo_ids,
            }
            self.adoptions[key] = record
            self._audit_log(actor, "adopt_amendment", "site", site_id,
                            {"amendment_id": amendment_id, "todos": todo_ids})
            return self._snapshot(record)

    def resolve_amendment_todo(
        self,
        actor: dict[str, Any],
        *,
        todo_id: str,
        resolution: str,
        rescheduled_activity_ids: Optional[list[str]] = None,
        note: str = "",
    ) -> dict[str, Any]:
        """确认逐人待办处置。并发重复确认幂等返回；不同处置冲突才报 409。

        - 补充同意：须先以该修订登记新版知情同意（record_consent 带 amendment_id）；
        - 重新排程：须先用 delay_activity 携带 amendment_id 重排至少一个活动；
        - 退出：退出修订、按原版本既有安排随访（冻结解除，但不迁移到新版本）；
        - 继续：无附加要求。
        """
        actor = self._actor(actor)
        self._require_role(actor, "研究者", "试验协调员")
        if resolution not in AMENDMENT_RESOLUTIONS:
            raise ValidationError(f"处置必须是：{'、'.join(AMENDMENT_RESOLUTIONS)}")
        with self._lock:
            todo = self._get(self.amendment_todos, "修订待办", todo_id)
            if todo["status"] == "已完成":
                done = todo["resolution"]
                if done["resolution"] != resolution:
                    raise StateConflictError(
                        f"待办已按 {done['resolution']} 完成，不能改为 {resolution}",
                        code="todo_resolution_conflict",
                    )
                return self._snapshot(todo)  # 幂等：并发确认得到同一结果
            if todo["status"] == "已失效":
                raise StateConflictError(
                    "待办已因受试者撤回等优先事件失效，不能再确认处置",
                    code="todo_invalidated",
                )
            if resolution not in todo["allowed_resolutions"]:
                raise StateConflictError(
                    f"治疗事实要求的处置为 {todo['required_resolution']}（退出始终允许），"
                    f"收到 {resolution}",
                    code="todo_resolution_mismatch",
                )
            amendment = self.amendments[todo["amendment_id"]]
            evidence: dict[str, Any] = {}
            sid = todo["subject_id"]
            if resolution == "补充同意":
                new_consent = self._find_amendment_consent(sid, todo["amendment_id"])
                if new_consent is None:
                    raise StateConflictError(
                        "须先按新同意书重新签署知情同意（consent 携带 amendment_id）",
                        code="amendment_reconsent_required",
                    )
                evidence["consent_id"] = new_consent["consent_id"]
            elif resolution == "重新排程":
                verified = self._amendment_reschedule_evidence(
                    sid, todo["amendment_id"],
                    rescheduled_activity_ids if rescheduled_activity_ids else None,
                )
                if not verified:
                    raise StateConflictError(
                        "须至少携带本修订完成一次活动改期（delay_activity 带 amendment_id）"
                        "或新建一次受影响活动排程（schedule_activity 带 amendment_id）",
                        code="amendment_reschedule_required",
                    )
                evidence["rescheduled_activity_ids"] = sorted(set(verified))
            now_iso = self._now().isoformat(timespec="seconds")
            todo["status"] = "已完成"
            todo["resolved_at"] = now_iso
            todo["resolution"] = {
                "resolution": resolution,
                "resolved_by": actor["id"],
                "at": now_iso,
                "note": note,
                **evidence,
            }
            subject = self.subjects[sid]
            subject.setdefault("amendments_applied", [])
            subject.setdefault("amendments_exited", [])
            if resolution == "退出":
                subject["amendments_exited"].append(todo["amendment_id"])
            elif resolution != "继续":
                if todo["amendment_id"] not in subject["amendments_applied"]:
                    subject["amendments_applied"].append(todo["amendment_id"])
            self._audit_log(actor, "resolve_amendment_todo", "amendment_todo", todo_id,
                            {"amendment_id": todo["amendment_id"],
                             "subject_id": sid, "resolution": resolution, **evidence})
            return self._snapshot(todo)

    def _find_amendment_consent(
        self, subject_id: str, amendment_id: str
    ) -> Optional[dict[str, Any]]:
        for consent in self.consents.values():
            if (consent["subject_id"] == subject_id
                    and consent.get("amendment_id") == amendment_id
                    and consent["status"] == "已签署"):
                return consent
        return None

    def _amendment_reschedule_evidence(
        self, subject_id: str, amendment_id: str,
        only_activity_ids: Optional[list[str]] = None,
    ) -> list[str]:
        """收集本修订下的重排证据：携带修订的改期历史，或携带修订新建的排程。"""
        out: list[str] = []
        restrict = set(only_activity_ids) if only_activity_ids else None
        for aid, act in self.activities.items():
            if act["subject_id"] != subject_id:
                continue
            if restrict is not None and aid not in restrict:
                continue
            hit = act.get("amendment_id") == amendment_id or any(
                h.get("amendment_id") == amendment_id
                for h in act.get("reschedule_history", [])
            )
            if hit:
                out.append(aid)
        return sorted(out)

    # ----- 修订阻断：冻结与待办的优先级判定 -----------------------------

    def _emergency_amendment_freeze(self, subject: dict[str, Any]) -> Optional[dict[str, Any]]:
        """紧急修订在安全委员会复核前对该方案下受试者全局冻结。"""
        for aid in self.amendment_order:
            amd = self.amendments[aid]
            if amd["status"] == "冻结生效中" and amd["protocol_id"] == subject["protocol_id"]:
                return amd
        return None

    def _open_amendment_todos(self, subject: dict[str, Any]) -> list[dict[str, Any]]:
        """中心已采用且尚未完成、处置为阻断型（补充同意/重新排程/退出）的待办。

        判定为“继续”的待办不暂停任何操作，仅需中心确认留痕。
        """
        sid = subject["subject_id"]
        out = []
        for tid in self.amendment_todo_order:
            todo = self.amendment_todos[tid]
            if todo["subject_id"] != sid or todo["status"] != "待处理":
                continue
            if (todo["amendment_id"], todo["site_id"]) not in self.adoptions:
                continue
            if todo["required_resolution"] == "继续":
                continue
            out.append(todo)
        return out

    def _amendment_blockers(self, subject: dict[str, Any]) -> list[dict[str, Any]]:
        """返回受试者当前的修订阻断（顺序固定：紧急冻结优先于逐人待办）。"""
        blockers: list[dict[str, Any]] = []
        freeze = self._emergency_amendment_freeze(subject)
        if freeze is not None:
            blockers.append({
                "code": "amendment_freeze",
                "message": (
                    f"紧急修订 {freeze['amendment_id']} 已先行冻结，"
                    f"须于 {freeze['review_due_at']} 前经安全委员会补审"
                ),
                "amendment_id": freeze["amendment_id"],
            })
            return blockers  # 冻结期间逐人待办尚未实例化，无需再列
        for todo in self._open_amendment_todos(subject):
            blockers.append({
                "code": "amendment_requirement_open",
                "message": (
                    f"修订 {todo['amendment_id']} 待处置：{todo['required_resolution']}"
                    f"（待办 {todo['todo_id']}）"
                ),
                "amendment_id": todo["amendment_id"],
                "todo_id": todo["todo_id"],
                "required_resolution": todo["required_resolution"],
            })
        return blockers

    def _require_no_amendment_hold(
        self, subject: dict[str, Any], *, bypass_amendment_id: Optional[str] = None
    ) -> None:
        """研究操作闸门：撤回/SAE 由各自闸门优先处理，修订阻断紧随其后。

        bypass_amendment_id 仅豁免该修订自身的逐人待办（用于关闭待办的补救动作：
        重新知情同意/改期）；紧急安全冻结与其他修订待办仍然阻断。
        """
        freeze = self._emergency_amendment_freeze(subject)
        if freeze is not None:
            raise StateConflictError(
                f"紧急修订 {freeze['amendment_id']} 已先行冻结，"
                f"须于 {freeze['review_due_at']} 前经安全委员会补审",
                code="amendment_freeze",
            )
        for todo in self._open_amendment_todos(subject):
            if bypass_amendment_id is not None and todo["amendment_id"] == bypass_amendment_id:
                continue
            raise StateConflictError(
                f"修订 {todo['amendment_id']} 待处置：{todo['required_resolution']}"
                f"（待办 {todo['todo_id']}）",
                code="amendment_requirement_open",
            )

    # ----- 修订视图：中心待办领取、受试者可执行动作、快照回溯 -----------

    def _todo_overdue(self, todo: dict[str, Any]) -> bool:
        if todo["status"] == "已完成" or not todo["due_at"]:
            return False
        return self._now() > _parse_dt(todo["due_at"])

    def _todo_view(self, todo: dict[str, Any]) -> dict[str, Any]:
        view = self._snapshot(todo)
        view["overdue"] = self._todo_overdue(todo)
        return view

    def list_site_todos(
        self, actor: dict[str, Any], site_id: str, *, status: Optional[str] = None
    ) -> list[dict[str, Any]]:
        """各中心领取本中心待办；盲态角色只能看到收窄后的运营字段。"""
        actor = self._actor(actor)
        if status is not None and status not in TODO_STATUSES:
            raise ValidationError(f"待办状态必须是：{'、'.join(TODO_STATUSES)}")
        with self._lock:
            self._get(self.sites, "中心", site_id)
            rows = []
            for tid in self.amendment_todo_order:
                todo = self.amendment_todos[tid]
                if todo["site_id"] != site_id:
                    continue
                if status and todo["status"] != status:
                    continue
                view = self._todo_view(todo)
                if actor["role"] == "盲态评价者":
                    view = {k: view.get(k) for k in BLIND_SAFE_TODO_FIELDS}
                    view["overdue"] = self._todo_overdue(todo)
                rows.append(view)
            return rows

    def subject_amendment_todos(
        self, actor: dict[str, Any], subject_id: str, *, open_only: bool = False
    ) -> list[dict[str, Any]]:
        actor = self._actor(actor)
        with self._lock:
            self._get(self.subjects, "受试者", subject_id)
            rows = []
            for tid in self.amendment_todo_order:
                todo = self.amendment_todos[tid]
                if todo["subject_id"] != subject_id:
                    continue
                if open_only and todo["status"] != "待处理":
                    continue
                view = self._todo_view(todo)
                if actor["role"] == "盲态评价者":
                    # 事实中含队列等剂量信息，盲态只能看运营状态
                    view = {k: view.get(k) for k in BLIND_SAFE_TODO_FIELDS}
                    view["overdue"] = self._todo_overdue(todo)
                rows.append(view)
            return rows

    def subject_available_actions(
        self, actor: dict[str, Any], subject_id: str
    ) -> dict[str, Any]:
        """查询受试者当前可执行动作（结果只取决于当前事实，不依赖请求到达顺序）。

        优先级固定：撤回同意 > 未关闭 SAE > 紧急修订冻结 > 修订逐人待办 > 常规闸门。
        盲态角色得到收窄视图：只见是否阻断与待办存在，不见剂量/器械/治疗时间线。
        """
        actor = self._actor(actor)
        with self._lock:
            subject = self._get(self.subjects, "受试者", subject_id)
            blockers: list[dict[str, Any]] = []
            if subject["withdrawn"]:
                blockers.append({"code": "subject_withdrawn",
                                 "message": "受试者已撤回同意，停止新增研究用途"})
            open_sae = self._open_sae(subject_id)
            if open_sae:
                blockers.append({"code": "sae_hold",
                                 "message": f"未关闭 SAE {open_sae['sae_id']}，治疗冻结",
                                 "sae_id": open_sae["sae_id"]})
            amendment_blockers = [] if blockers else self._amendment_blockers(subject)
            blockers.extend(amendment_blockers)

            def gate(reason_codes=()):
                hit = next((b for b in blockers if not reason_codes or b["code"] in reason_codes), None)
                return {"allowed": hit is None, "blocked_by": None if hit is None else {
                    "code": hit["code"], "message": hit["message"]}}

            open_todos = [
                self._todo_view(t) for t in self._open_amendment_todos(subject)
            ]
            freeze = self._emergency_amendment_freeze(subject)
            data: dict[str, Any] = {
                "subject_id": subject_id,
                "site_id": subject["site_id"],
                "status": subject["status"],
                "protocol_version": subject["protocol_version"],
                "blocked": bool(blockers),
                "blocking_reasons": blockers,
                "actions": {
                    "schedule_treatment": gate(),
                    "perform_treatment": gate(),
                    "schedule_visit": gate(),
                    "register_artifact": gate(),
                    "record_outcome": gate(),
                    "reschedule_activity": {"allowed": False, "blocked_by": None},
                    "amendment_reconsent": {"allowed": False, "blocked_by": None},
                    "resolve_amendment_todo": {"allowed": False, "blocked_by": None},
                    # 以下动作任何修订阻断都不能拦截：SAE 随时可报（撤回后安全记录仍保留）
                    "record_sae": {"allowed": True, "blocked_by": None},
                    "withdraw_consent": {"allowed": not subject["withdrawn"], "blocked_by": None},
                },
                "open_amendment_todos": open_todos,
                "emergency_freeze": None if freeze is None else {
                    "amendment_id": freeze["amendment_id"],
                    "review_due_at": freeze["review_due_at"],
                    "overdue": bool(freeze["review_due_at"]
                                    and self._now() > _parse_dt(freeze["review_due_at"])),
                },
            }
            # 修订框架内的补救动作
            reschedule_bypass = next(
                (t for t in open_todos if t["required_resolution"] == "重新排程"), None)
            data["actions"]["reschedule_activity"] = {
                "allowed": reschedule_bypass is not None
                           and self._emergency_amendment_freeze(subject) is None,
                "blocked_by": None,
                "amendment_id": None if reschedule_bypass is None
                else reschedule_bypass["amendment_id"],
            }
            reconsent_todo = next(
                (t for t in open_todos if t["required_resolution"] == "补充同意"), None)
            data["actions"]["amendment_reconsent"] = {
                "allowed": reconsent_todo is not None
                           and self._emergency_amendment_freeze(subject) is None,
                "amendment_id": None if reconsent_todo is None
                else reconsent_todo["amendment_id"],
            }
            data["actions"]["resolve_amendment_todo"] = {
                "allowed": bool(open_todos),
                "open_todo_ids": [t["todo_id"] for t in open_todos],
            }
            # “继续”型待办也需要中心确认（但不阻断操作）
            confirm_only = [
                self._todo_view(t) for t in self.amendment_todos.values()
                if t["subject_id"] == subject_id and t["status"] == "待处理"
                and (t["amendment_id"], t["site_id"]) in self.adoptions
                and t["required_resolution"] == "继续"
            ]
            data["confirmation_only_todos"] = confirm_only
            if confirm_only:
                data["actions"]["resolve_amendment_todo"]["allowed"] = True
                data["actions"]["resolve_amendment_todo"]["open_todo_ids"] += [
                    t["todo_id"] for t in confirm_only]

            if actor["role"] == "盲态评价者":
                return self._blind_actions_view(data)
            return data

    def _blind_actions_view(self, data: dict[str, Any]) -> dict[str, Any]:
        safe = {
            "subject_id": data["subject_id"],
            "site_id": data["site_id"],
            "status": data["status"],
            "blocked": data["blocked"],
            "blocking_reasons": [
                {"code": b["code"]} for b in data["blocking_reasons"]
            ],
            "open_amendment_todos": [
                {k: t.get(k) for k in BLIND_SAFE_TODO_FIELDS} | {"overdue": t.get("overdue")}
                for t in data["open_amendment_todos"]
            ],
            "actions": {
                "record_sae": data["actions"]["record_sae"],
                "withdraw_consent": data["actions"]["withdraw_consent"],
            },
        }
        return safe

    def list_amendments(self, actor: dict[str, Any]) -> list[dict[str, Any]]:
        actor = self._actor(actor)
        if actor["role"] == "盲态评价者":
            raise PermissionDeniedError("盲态角色不得接触方案修订实质内容")
        with self._lock:
            return [self._amendment_view(self.amendments[aid])
                    for aid in self.amendment_order]

    def get_amendment(self, actor: dict[str, Any], amendment_id: str) -> dict[str, Any]:
        actor = self._actor(actor)
        if actor["role"] == "盲态评价者":
            raise PermissionDeniedError("盲态角色不得接触方案修订实质内容")
        with self._lock:
            record = self._get(self.amendments, "修订", amendment_id)
            return self._amendment_view(record)

    def amendment_snapshots(self, actor: dict[str, Any], amendment_id: str) -> list[dict[str, Any]]:
        actor = self._actor(actor)
        if actor["role"] == "盲态评价者":
            raise PermissionDeniedError("盲态角色不得接触修订影响快照")
        with self._lock:
            record = self._get(self.amendments, "修订", amendment_id)
            if record["status"] != "已批准":
                raise StateConflictError("修订批准后才生成逐受试者影响快照",
                                         code="amendment_not_approved")
            return self._snapshot(record["snapshots"])

    def _amendment_view(self, record: dict[str, Any]) -> dict[str, Any]:
        view = self._snapshot(record)
        view["overdue"] = (
            record["status"] == "冻结生效中"
            and record["review_due_at"] is not None
            and self._now() > _parse_dt(record["review_due_at"])
        )
        view["adopting_site_ids"] = sorted(
            site_id for (aid, site_id) in self.adoptions if aid == record["amendment_id"]
        )
        return view

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
        amendment_id: Optional[str] = None,
    ) -> dict[str, Any]:
        """登记知情同意：同意书必须对应某方案版本，留存引用与校验值。

        携带 amendment_id 时为修订后的重新知情同意：protocol_version 可为修订声明的
        新版本（即使该版本尚未单独建档），同意链接到已批准修订，用于关闭“补充同意”待办。
        """
        actor = self._actor(actor)
        self._require_role(actor, "研究者", "试验协调员")
        signed = _parse_dt(signed_at)
        with self._lock:
            subject = self._get(self.subjects, "受试者", subject_id)
            if subject["withdrawn"]:
                raise StateConflictError("受试者已撤回，不得登记新同意")
            linked_amendment = None
            if amendment_id is not None:
                linked_amendment = self._get(self.amendments, "修订", amendment_id)
                if linked_amendment["status"] != "已批准":
                    raise StateConflictError(
                        "修订尚未获安全委员会批准，不能据其登记新版同意",
                        code="amendment_not_approved",
                    )
                if protocol_version != linked_amendment["new_version"]:
                    raise ValidationError(
                        "重新知情同意的方案版本必须与修订新版本一致："
                        + linked_amendment["new_version"]
                    )
                proto = self.protocols[linked_amendment["protocol_id"]]
            else:
                proto = self._find_protocol_by_version(protocol_version)
            # 紧急安全修订冻结期间，重新知情同意等研究流程一并暂停
            # （SAE 上报与撤回同意不受此限）；修订同意豁免该修订自身的待办
            self._require_no_amendment_hold(
                subject,
                bypass_amendment_id=None if linked_amendment is None
                else linked_amendment["amendment_id"],
            )
            cid = consent_id or _new_id("icf")
            if cid in self.consents:
                raise StateConflictError(f"同意记录已存在：{cid}")
            record = {
                "consent_id": cid,
                "subject_id": subject_id,
                "protocol_id": proto["protocol_id"],
                "protocol_version": protocol_version,
                "consent_version": consent_version,
                "document_ref": document_ref,
                "document_checksum": document_checksum,
                "status": "已签署",
                "signed_at": signed.isoformat(timespec="seconds"),
                "withdrawn_at": None,
                "amendment_id": amendment_id,
            }
            self.consents[cid] = record
            subject["consent_id"] = cid
            self._audit_log(actor, "record_consent", "consent", cid,
                            {"subject_id": subject_id,
                             "protocol_version": proto["version"],
                             "amendment_id": amendment_id})
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
            # 撤回同意始终优先：该受试者所有未完成的修订待办一律失效，
            # 中心不再被要求补同意/重排/退出，既有治疗与安全记录仍保留
            invalidated = self._invalidate_subject_todos(
                subject_id, at_dt.isoformat(timespec="seconds"), reason=reason)
            if subject["status"] in ("筛选中",):
                subject["status"] = "已撤回"
            self._audit_log(actor, "withdraw_consent", "subject", subject_id,
                            {"reason": reason, "retained": "safety_records",
                             "invalidated_todos": invalidated})
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
            # 紧急安全修订先冻结：补审未完成前暂停该方案的一切新增暴露（含新入组）
            if self._emergency_amendment_freeze(
                    {"protocol_id": proto["protocol_id"]}) is not None:
                raise StateConflictError(
                    "该方案存在紧急安全修订冻结中，安全委员会补审前暂停入组",
                    code="amendment_freeze",
                )
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
            self._require_no_amendment_hold(subject)
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
            # 紧急安全修订冻结同样不能被紧急偏离绕过
            freeze = self._emergency_amendment_freeze(subject)
            if freeze is not None:
                raise StateConflictError(
                    f"紧急修订 {freeze['amendment_id']} 冻结生效中，"
                    "紧急偏离不能覆盖修订冻结，须先经安全委员会补审",
                    code="amendment_freeze",
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
                    self._invalidate_subject_todos(
                        record["subject_id"], review["at"],
                        reason=f"SAE {sae_id} 终止决议")
            self._audit_log(actor, "review_sae", "sae", sae_id, review)
            return self._snapshot(record)

    def _invalidate_subject_todos(
        self, subject_id: str, at_iso: str, *, reason: str
    ) -> list[str]:
        """撤回（含 SAE 终止决议）始终优先：未完成修订待办一律失效留痕。"""
        invalidated = []
        at_dt = _parse_dt(at_iso)
        for tid in self.amendment_todo_order:
            todo = self.amendment_todos[tid]
            if todo["subject_id"] != subject_id or todo["status"] != "待处理":
                continue
            todo["status"] = "已失效"
            todo["resolved_at"] = at_dt.isoformat(timespec="seconds")
            todo["resolution"] = {"resolution": "撤回优先-自动失效",
                                  "at": at_dt.isoformat(timespec="seconds"),
                                  "reason": reason}
            invalidated.append(tid)
        return invalidated

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
        amendment_id: Optional[str] = None,
    ) -> dict[str, Any]:
        """排程研究活动（注射/激光照射/手术评估/影像/病理/访视）。

        治疗类活动排程即校验：方案放行、中心资质、批次不涉及（执行时校验）、
        SAE 冻结、撤回与越窗。携带 amendment_id 时仅允许在该修订“重新排程”
        待办下新建受影响活动（新建排程本身即补救动作）。
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
                self._treatment_gate(
                    subject, at=planned, for_scheduling=True,
                    amendment_bypass=amendment_id,
                )
            else:
                self._emergency_review_gate(subject_id)
                self._require_no_amendment_hold(subject)
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
                "amendment_id": amendment_id,
                "notes": "",
            }
            self.activities[aid] = record
            self._audit_log(actor, "schedule_activity", "activity", aid,
                            {"subject_id": subject_id, "kind": kind,
                             "planned_at": record["planned_at"],
                             "amendment_id": amendment_id})
            return self._snapshot(record)

    def _treatment_gate(
        self, subject: dict[str, Any], *, at: datetime, for_scheduling: bool,
        check_emergency: bool = True,
        amendment_bypass: Optional[str] = None,
    ) -> None:
        """治疗前阻断规则：错误方案/SAE/撤回/未分配队列一律阻止。

        执行紧急偏离的目标活动时由调用方传 check_emergency=False 自行豁免。
        amendment_bypass 传入修订 id 时，若该受试者正有该修订的“重新排程”待办，
        允许其改期动作（改期本身即补救要求）；其余修订冻结/待办仍然阻断。
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
        if amendment_bypass is None:
            self._require_no_amendment_hold(subject)
        else:
            # 仅豁免该修订自身的逐人待办；紧急冻结或他修订待办仍阻断
            self._require_no_amendment_hold(subject, bypass_amendment_id=amendment_bypass)
            if not self._has_reschedule_todo(sid, amendment_bypass):
                raise StateConflictError(
                    "该受试者没有此修订的待处理“重新排程”待办，不能借修订改期",
                    code="amendment_reschedule_required",
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

    def _has_reschedule_todo(self, subject_id: str, amendment_id: str) -> bool:
        tid = f"{amendment_id}:{self.subjects[subject_id]['site_id']}:{subject_id}"
        todo = self.amendment_todos.get(tid)
        return (
            todo is not None
            and todo["status"] == "待处理"
            and todo["required_resolution"] == "重新排程"
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
                # 修订紧急冻结与逐人待办同样不能被紧急偏离绕过
                # （安全规则修订与重新知情同意优先于先行处置）
                self._require_no_amendment_hold(subject)
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
        self, actor: dict[str, Any], *, activity_id: str, new_planned_at: Any,
        reason: str, amendment_id: Optional[str] = None,
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
                self._treatment_gate(
                    subject, at=new_at, for_scheduling=True,
                    amendment_bypass=amendment_id,
                )
            else:
                self._require_no_amendment_hold(subject)
                self._window_gate(subject, new_at)
            if amendment_id is not None:
                amd = self._get(self.amendments, "修订", amendment_id)
                if amd["status"] != "已批准":
                    raise StateConflictError(
                        "修订尚未获安全委员会批准，不能据此改期",
                        code="amendment_not_approved",
                    )
                if not self._has_reschedule_todo(subject["subject_id"], amendment_id):
                    raise StateConflictError(
                        "该受试者没有此修订的待处理“重新排程”待办，不能借修订改期",
                        code="amendment_reschedule_required",
                    )
            old = record["planned_at"]
            record["planned_at"] = new_at.isoformat(timespec="seconds")
            record.setdefault("reschedule_history", []).append(
                {"from": old, "to": record["planned_at"], "reason": reason,
                 "by": actor["id"], "at": self._now().isoformat(timespec="seconds"),
                 "amendment_id": amendment_id}
            )
            self._audit_log(actor, "delay_activity", "activity", activity_id,
                            {"from": old, "to": record["planned_at"], "reason": reason,
                             "amendment_id": amendment_id})
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
            self._require_no_amendment_hold(subject)
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
            self._require_no_amendment_hold(subject)
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
            self._require_no_amendment_hold(subject)
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
        amendment_ids = [a["amendment_id"] for a in self.amendments.values()
                         if a["protocol_id"] == proto["protocol_id"]]
        decisions = [d for d in self.decisions
                     if d["target_id"] in (proto["protocol_id"], *sae_ids, *amendment_ids)]
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
            "amendments": self._subject_amendment_trace(sid, proto["protocol_id"]),
            "consent_id": subject["consent_id"],
            "enrolled_at": subject["enrolled_at"],
        }

    def _subject_amendment_trace(
        self, subject_id: str, protocol_id: str
    ) -> list[dict[str, Any]]:
        """受试者维度的修订溯源：批准快照判定、中心采用、逐人处置全程留痕。"""
        rows = []
        for aid in self.amendment_order:
            amd = self.amendments[aid]
            if amd["protocol_id"] != protocol_id:
                continue
            site_id = self.subjects[subject_id]["site_id"]
            adoption = self.adoptions.get((aid, site_id))
            todo = self.amendment_todos.get(f"{aid}:{site_id}:{subject_id}")
            snap = next(
                (row for row in amd["snapshots"] if row["subject_id"] == subject_id), None)
            rows.append({
                "amendment_id": aid,
                "new_version": amd["new_version"],
                "status": amd["status"],
                "emergency": amd["emergency"],
                "impact_domains": list(amd["impact"]),
                "review": amd["review"],
                "approved_snapshot_decision": None if snap is None else snap["decision"],
                "adopted": adoption is not None,
                "todo": None if todo is None else {
                    "todo_id": todo["todo_id"],
                    "status": todo["status"],
                    "required_resolution": todo["required_resolution"],
                    "resolution": todo["resolution"],
                },
            })
        return rows

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
