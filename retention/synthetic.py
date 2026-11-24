# -*- coding: utf-8 -*-
"""本地合成数据：虚构租户、主体、委托链、案件与旧结案摘要。

不联网、不读取真实案件数据。两个租户（alpha / beta）可引用同一份原始摘要，
但 beta 必须持有自己的 XREF_APPROVAL 批准。
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from .model import Grant, Principal, Role, Seat, SignoffRequest

TENANT_A = "tenant-alpha"
TENANT_B = "tenant-beta"
CASE_A = "CASE-A-100"
CASE_B = "CASE-B-200"
SUMMARY = "SUMMARY-SYN-5001"          # 被引用的同一份原始摘要
EPOCH_INITIAL = 1
EPOCH_AFTER_REVOKE = 2

# ------------------------------------------------------------------
# 主体（委托链：delegated_from 指向上一级授权人）
# ------------------------------------------------------------------
PRINCIPALS: dict[str, Principal] = {
    # alpha 租户：一名直接授权管理员 + 一名受委托管理员
    "a-admin-1": Principal("a-admin-1", Role.ADMIN, TENANT_A),
    "a-admin-2": Principal("a-admin-2", Role.ADMIN, TENANT_A,
                           delegated_from="a-admin-1"),
    # alpha 租户：两名委托根不同的独立见证人 -> 合法两席
    "a-wit-r1": Principal("a-wit-r1", Role.WITNESS, TENANT_A),
    "a-wit-r2": Principal("a-wit-r2", Role.WITNESS, TENANT_A),
    # 第三名见证人委托自 a-wit-r1 -> 与 a-wit-r1 共享源头，只能算一席
    "a-wit-r1-delegate": Principal("a-wit-r1-delegate", Role.WITNESS,
                                   TENANT_A, delegated_from="a-wit-r1"),
    # beta 租户自己的管理员与见证人（席位不与 alpha 通用）
    "b-admin-1": Principal("b-admin-1", Role.ADMIN, TENANT_B),
    "b-wit-r1": Principal("b-wit-r1", Role.WITNESS, TENANT_B),
    "b-wit-r2": Principal("b-wit-r2", Role.WITNESS, TENANT_B),
}

# ------------------------------------------------------------------
# 授权（epoch=1 为初始授权代；gid 与主体同名便于阅读）
# ------------------------------------------------------------------
GRANTS: dict[str, Grant] = {
    "g-a-admin-1": Grant("g-a-admin-1", "a-admin-1", TENANT_A, CASE_A,
                         Role.ADMIN, EPOCH_INITIAL),
    "g-a-admin-2": Grant("g-a-admin-2", "a-admin-2", TENANT_A, CASE_A,
                         Role.ADMIN, EPOCH_INITIAL,
                         delegated_from="a-admin-1"),
    "g-a-wit-r1": Grant("g-a-wit-r1", "a-wit-r1", TENANT_A, CASE_A,
                        Role.WITNESS, EPOCH_INITIAL),
    "g-a-wit-r2": Grant("g-a-wit-r2", "a-wit-r2", TENANT_A, CASE_A,
                        Role.WITNESS, EPOCH_INITIAL),
    # 授权 gid 采用 g-<pid> 约定，synthetic.seat 据此定位授权
    "g-a-wit-r1-delegate": Grant(
        "g-a-wit-r1-delegate", "a-wit-r1-delegate", TENANT_A,
        CASE_A, Role.WITNESS, EPOCH_INITIAL,
        delegated_from="a-wit-r1"),
    "g-b-admin-1": Grant("g-b-admin-1", "b-admin-1", TENANT_B, CASE_B,
                         Role.ADMIN, EPOCH_INITIAL),
    "g-b-wit-r1": Grant("g-b-wit-r1", "b-wit-r1", TENANT_B, CASE_B,
                        Role.WITNESS, EPOCH_INITIAL),
    "g-b-wit-r2": Grant("g-b-wit-r2", "b-wit-r2", TENANT_B, CASE_B,
                        Role.WITNESS, EPOCH_INITIAL),
}

XREF_APPROVAL_ID = "xref-beta-syn5001"


def grant_event(grant: Grant) -> dict[str, Any]:
    p = PRINCIPALS[grant.pid]
    return {
        "kind": "GRANT", "gid": grant.gid, "pid": grant.pid,
        "tenant": grant.tenant, "case_id": grant.case_id,
        "role": grant.role.value, "epoch": grant.epoch,
        "delegated_from": p.delegated_from,
    }


def revoke_event(grant_id: str, revoke_epoch: int = EPOCH_AFTER_REVOKE
                 ) -> dict[str, Any]:
    return {"kind": "REVOKE", "gid": grant_id,
            "revoke_epoch": revoke_epoch}


def xref_approval_event(approval_id: str = XREF_APPROVAL_ID,
                        revoked: bool = False) -> dict[str, Any]:
    return {
        "kind": "XREF_APPROVAL", "approval_id": approval_id,
        "tenant": TENANT_B, "source_tenant": TENANT_A,
        "summary_id": SUMMARY, "bound_summary_id": SUMMARY,
        "revoked": revoked,
    }


def xref_revoke_event(approval_id: str = XREF_APPROVAL_ID
                      ) -> dict[str, Any]:
    return {"kind": "XREF_REVOKE", "approval_id": approval_id}


def seat(pid: str, epoch: int = EPOCH_INITIAL) -> Seat:
    """按约定用 g-<pid> 找到该主体的授权，构造绑定指定授权代的席位。"""
    gid = f"g-{pid}"
    return Seat(pid=pid, role=PRINCIPALS[pid].role,
                grant_id=gid, epoch=epoch)


def make_request(
    request_id: str,
    tenant: str,
    case_id: str,
    pids: list[str],
    *,
    bound_epoch: int = EPOCH_INITIAL,
    summary_id: str = SUMMARY,
    source_summary_tenant: str | None = None,
) -> SignoffRequest:
    return SignoffRequest(
        request_id=request_id, tenant=tenant, case_id=case_id,
        summary_id=summary_id, bound_epoch=bound_epoch,
        seats=tuple(seat(pid, bound_epoch) for pid in pids),
        source_summary_tenant=source_summary_tenant,
    )


def with_stale_epoch(req: SignoffRequest,
                     stale_epoch: int = EPOCH_INITIAL) -> SignoffRequest:
    """把签收冻结在旧授权代（用于撤销后仍提交旧承诺的场景）。"""
    return replace(
        req, bound_epoch=stale_epoch,
        seats=tuple(replace(s, epoch=stale_epoch) for s in req.seats))


def base_grant_events(tenant: str = TENANT_A) -> list[dict[str, Any]]:
    """某租户初始授权集对应的 GRANT 事件序列。"""
    prefix = "g-a-" if tenant == TENANT_A else "g-b-"
    return [grant_event(g) for gid, g in GRANTS.items()
            if gid.startswith(prefix)]


def commit_event(req: SignoffRequest) -> dict[str, Any]:
    from .replay import request_to_event
    return {"kind": "COMMIT", "request": request_to_event(req)}
