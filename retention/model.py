# -*- coding: utf-8 -*-
"""领域模型与纯函数签收规则引擎（无 I/O、无线程，可被状态机与重放器复用）。

所有主体、案件、摘要均为合成数据。核心规则（对应题面）：

1. 每条结案摘要只可由「案件管理员」与「独立见证人」共同签收；
2. 权限可委托，委托链上的授权可被逐代撤销，撤销即产生新「授权代(epoch)」；
3. 两个见证人若共享同一委托源头，只能算一席（去重按委托根）；
4. 合格签收必须绑定：案件编号、原始摘要标识、签收时的授权代；
5. 另一租户可引用同一原始摘要，但必须持有自己租户的独立批准（XREF_APPROVAL），
   且席位与原始租户的席位互不通用。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import FrozenSet, Iterable, Mapping, Optional, Tuple


class Role(str, Enum):
    ADMIN = "case_admin"          # 案件管理员
    WITNESS = "independent_witness"  # 独立见证人


class RejectReason(str, Enum):
    OK = "OK"
    SEAT_COUNT = "席位不足：需至少一名管理员席与两名独立见证人席"
    SHARED_WITNESS_ROOT = "共享源头：两名见证人委托根相同，只能算一席"
    DELEGATION_REVOKED = "委托链上的授权已被撤销"
    STALE_EPOCH = "授权代不匹配：签收依据的授权代已过期"
    WRONG_TENANT = "授权与申请的租户不一致"
    WRONG_CASE = "授权未覆盖该案件"
    WRONG_SUMMARY = "签收未绑定正确的原始摘要"
    ROLE_MISMATCH = "主体角色与所声称的席位角色不一致"
    XREF_MISSING = "跨租户引用缺少本租户的独立批准"
    XREF_REVOKED = "跨租户引用的批准已被撤销"
    XREF_WRONG_TARGET = "跨租户引用批准指向的原始摘要与申请不一致"


@dataclass(frozen=True)
class Principal:
    """签收主体。delegated_from 指向上一级授权人，None 表示直接授权的根主体。"""

    pid: str
    role: Role
    tenant: str
    delegated_from: Optional[str] = None


@dataclass(frozen=True)
class Grant:
    """一次授权（授权链上的一环）。epoch 为授权代，单调递增。"""

    gid: str
    pid: str
    tenant: str
    case_id: str
    role: Role
    epoch: int
    delegated_from: Optional[str] = None  # 授权来自哪个主体（委托链）


@dataclass(frozen=True)
class Revocation:
    """对某次授权的撤销。撤销代 revoke_epoch 之后，旧授权代立即失效。"""

    gid: str
    revoke_epoch: int


@dataclass(frozen=True)
class Seat:
    """签收申请中提交的一个席位。"""

    pid: str
    role: Role
    grant_id: str
    epoch: int  # 签收时绑定的授权代


@dataclass(frozen=True)
class SignoffRequest:
    """一次签收申请：必须绑定案件、原始摘要与授权代。"""

    request_id: str
    tenant: str
    case_id: str
    summary_id: str          # 原始结案摘要标识
    seats: Tuple[Seat, ...]
    bound_epoch: int         # 整个签收绑定的授权代（取席位依据的代）
    source_summary_tenant: Optional[str] = None  # 仅跨租户引用时填写


@dataclass(frozen=True)
class Verdict:
    accepted: bool
    reason: RejectReason
    detail: str = ""
    # 去重后的见证人委托根（证据用途）
    witness_roots: Tuple[str, ...] = field(default_factory=tuple)
    admin_seats: int = 0
    witness_seats: int = 0


def delegation_root(pid: str, principals: Mapping[str, Principal]) -> str:
    """沿 delegated_from 上溯到委托根（直接授权主体）。

    两个见证人若 root 相同，即「共享源头」。
    委托深度做有限保护，避免合成数据成环导致死循环。
    """
    seen: set[str] = set()
    cur = pid
    while True:
        p = principals.get(cur)
        if p is None or p.delegated_from is None:
            return cur
        if cur in seen:  # 防御：合成数据不应成环
            raise ValueError(f"委托链成环: {pid}")
        seen.add(cur)
        cur = p.delegated_from


def _grant_active(
    grant: Grant,
    revocations: Mapping[str, Revocation],
    at_epoch: int,
) -> bool:
    """授权在授权代 at_epoch 是否仍然有效（授权代匹配且未被撤销）。"""
    if grant.epoch != at_epoch:
        return False
    rev = revocations.get(grant.gid)
    if rev is not None and rev.revoke_epoch <= at_epoch:
        return False
    return True


def evaluate(
    req: SignoffRequest,
    principals: Mapping[str, Principal],
    grants: Mapping[str, Grant],
    revocations: Mapping[str, Revocation],
    xref_approvals: Iterable[Mapping[str, object]] = (),
    current_epoch: int = 1,
) -> Verdict:
    """纯函数裁决：给定某个授权代快照下的授权/撤销状态，裁决签收申请。

    xref_approvals 为跨租户引用批准记录集合，每条包含
    summary_id / source_tenant / tenant / revoked(bool)。
    current_epoch 为裁决时刻的当前授权代；签收绑定代一旦落后即视为陈旧。
    """
    # 授权代是签收的强制绑定项：代已经前移，旧代承诺不得再入档
    if req.bound_epoch != current_epoch:
        return Verdict(
            False, RejectReason.STALE_EPOCH,
            f"签收绑定授权代 {req.bound_epoch}，当前授权代 {current_epoch}")

    admin_pids: list[str] = []
    witness_roots: list[str] = []

    for seat in req.seats:
        principal = principals.get(seat.pid)
        grant = grants.get(seat.grant_id)

        if principal is None:
            return Verdict(False, RejectReason.ROLE_MISMATCH,
                           f"未知主体 {seat.pid}")
        if grant is None:
            return Verdict(False, RejectReason.DELEGATION_REVOKED,
                           f"未知授权 {seat.grant_id}")
        if principal.role != seat.role or grant.role != seat.role:
            return Verdict(False, RejectReason.ROLE_MISMATCH,
                           f"{seat.pid} 角色与席位声称不一致")
        if grant.pid != seat.pid:
            return Verdict(False, RejectReason.ROLE_MISMATCH,
                           f"授权 {seat.grant_id} 不属于 {seat.pid}")
        if grant.tenant != req.tenant or principal.tenant != req.tenant:
            return Verdict(False, RejectReason.WRONG_TENANT,
                           f"{seat.pid} 的授权不属于租户 {req.tenant}")
        if grant.case_id != req.case_id:
            return Verdict(False, RejectReason.WRONG_CASE,
                           f"{seat.pid} 的授权未覆盖案件 {req.case_id}")
        if seat.epoch != req.bound_epoch:
            return Verdict(False, RejectReason.STALE_EPOCH,
                           f"席位 {seat.pid} 绑定代 {seat.epoch} "
                           f"!= 签收代 {req.bound_epoch}")
        if not _grant_active(grant, revocations, req.bound_epoch):
            # 区分「代过期」与「链上撤销」两类失败，便于证据阅读
            if grant.epoch != req.bound_epoch:
                return Verdict(False, RejectReason.STALE_EPOCH,
                               f"{seat.pid} 使用过期授权代 {seat.epoch}")
            return Verdict(False, RejectReason.DELEGATION_REVOKED,
                           f"{seat.pid} 的授权 {grant.gid} 已在授权代 "
                           f"{revocations[grant.gid].revoke_epoch} 被撤销")

        if seat.role == Role.ADMIN:
            admin_pids.append(seat.pid)
        else:
            root = delegation_root(seat.pid, principals)
            witness_roots.append(root)

    # 同一主体重复提交不增加席位
    unique_roots: FrozenSet[str] = frozenset(witness_roots)
    if len(witness_roots) != len(unique_roots):
        dup = sorted({r for r in witness_roots if witness_roots.count(r) > 1})
        return Verdict(
            False, RejectReason.SHARED_WITNESS_ROOT,
            f"见证人共享委托根 {dup}，按规则只能算一席",
            witness_roots=tuple(sorted(unique_roots)),
            admin_seats=len(set(admin_pids)),
            witness_seats=len(unique_roots),
        )

    n_admin = len(set(admin_pids))
    n_witness = len(unique_roots)
    base = Verdict(
        accepted=True, reason=RejectReason.OK,
        witness_roots=tuple(sorted(unique_roots)),
        admin_seats=n_admin, witness_seats=n_witness,
    )

    if n_admin < 1 or n_witness < 2:
        return Verdict(
            False, RejectReason.SEAT_COUNT,
            f"管理员席={n_admin} 见证人席={n_witness}（要求 >=1 与 >=2）",
            witness_roots=tuple(sorted(unique_roots)),
            admin_seats=n_admin, witness_seats=n_witness,
        )

    # 跨租户引用：本租户必须持有自己的、指向同一原始摘要的有效批准
    if req.source_summary_tenant is not None and \
            req.source_summary_tenant != req.tenant:
        matched = [
            a for a in xref_approvals
            if a["summary_id"] == req.summary_id
            and a["source_tenant"] == req.source_summary_tenant
            and a["tenant"] == req.tenant
        ]
        if not matched:
            return Verdict(False, RejectReason.XREF_MISSING,
                           f"租户 {req.tenant} 缺少对原始摘要 "
                           f"{req.source_summary_tenant}/{req.summary_id} "
                           f"的自有批准")
        approval = matched[-1]
        if approval.get("revoked"):
            return Verdict(False, RejectReason.XREF_REVOKED,
                           "跨租户引用批准已被撤销")
        if approval.get("bound_summary_id") not in (None, req.summary_id):
            return Verdict(False, RejectReason.XREF_WRONG_TARGET,
                           "引用批准指向的原始摘要与申请不一致")

    if not req.summary_id or not req.case_id:
        return Verdict(False, RejectReason.WRONG_SUMMARY,
                       "签收必须绑定案件与原始摘要")
    return base
