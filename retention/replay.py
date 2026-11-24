# -*- coding: utf-8 -*-
"""无状态重放裁决器：只读取磁盘日志，重建授权状态并逐条裁决。

产物（全部为实际落盘文件，可作为证据）
--------------------------------------
* decisions.jsonl  ：可重放的逐条决定（含落盘 seq、裁决理由、见证委托根）
* public_index/<租户>.json：公开索引，仅包含被接受的签收；失败记录禁止进入
* quarantine/<申请号>.json ：失败记录及其原因（隔离区，不进公开索引）
* receipts/<申请号>.receipt.json：接受签收的回执（幂等重派生，可恢复丢失回执）
"""

from __future__ import annotations

import json
import os
from typing import Any

from .journal import read_journal
from .model import (
    Grant,
    Principal,
    Revocation,
    Role,
    Seat,
    SignoffRequest,
    evaluate,
)


def _write_json(path: str, obj: Any) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(obj, fh, ensure_ascii=False, indent=2, sort_keys=True)
        fh.write("\n")
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)  # 原子替换，公开索引不会出现半写状态


def replay(journal_path: str, out_dir: str) -> dict[str, Any]:
    """重放 journal_path，把证据产物写入 out_dir，返回统计摘要。"""
    events = read_journal(journal_path)

    principals: dict[str, Principal] = {}
    grants: dict[str, Grant] = {}
    revocations: dict[str, Revocation] = {}
    xref: dict[str, dict[str, Any]] = {}
    current_epoch = 1  # 当前授权代：每次撤销前移一代

    decisions: list[dict[str, Any]] = []
    public_index: dict[str, dict[str, list[dict[str, Any]]]] = {}
    accepted_ids: set[str] = set()
    rejected_ids: set[str] = set()

    pub_dir = os.path.join(out_dir, "public_index")
    q_dir = os.path.join(out_dir, "quarantine")
    rcpt_dir = os.path.join(out_dir, "receipts")
    for d in (pub_dir, q_dir, rcpt_dir):
        os.makedirs(d, exist_ok=True)

    for ev in events:
        kind = ev["kind"]

        if kind == "GRANT":
            principals[ev["pid"]] = Principal(
                pid=ev["pid"], role=Role(ev["role"]),
                tenant=ev["tenant"], delegated_from=ev.get("delegated_from"),
            )
            grants[ev["gid"]] = Grant(
                gid=ev["gid"], pid=ev["pid"], tenant=ev["tenant"],
                case_id=ev["case_id"], role=Role(ev["role"]),
                epoch=ev["epoch"], delegated_from=ev.get("delegated_from"),
            )

        elif kind == "REVOKE":
            revocations[ev["gid"]] = Revocation(
                gid=ev["gid"], revoke_epoch=ev["revoke_epoch"])
            # 撤销即换代：此后仍绑定旧授权代的承诺一律按陈旧处理
            current_epoch = max(current_epoch, ev["revoke_epoch"])

        elif kind == "XREF_APPROVAL":
            xref[ev["approval_id"]] = dict(ev, revoked=False)

        elif kind == "XREF_REVOKE":
            if ev["approval_id"] in xref:
                xref[ev["approval_id"]]["revoked"] = True

        elif kind == "COMMIT":
            req_d = ev["request"]
            req = SignoffRequest(
                request_id=req_d["request_id"],
                tenant=req_d["tenant"],
                case_id=req_d["case_id"],
                summary_id=req_d["summary_id"],
                seats=tuple(
                    Seat(pid=s["pid"], role=Role(s["role"]),
                         grant_id=s["grant_id"], epoch=s["epoch"])
                    for s in req_d["seats"]
                ),
                bound_epoch=req_d["bound_epoch"],
                source_summary_tenant=req_d.get("source_summary_tenant"),
            )
            verdict = evaluate(
                req, principals, grants, revocations, xref.values(),
                current_epoch=current_epoch)

            decision = {
                "seq": ev["seq"],
                "request_id": req.request_id,
                "tenant": req.tenant,
                "case_id": req.case_id,
                "summary_id": req.summary_id,
                "bound_epoch": req.bound_epoch,
                "source_summary_tenant": req.source_summary_tenant,
                "accepted": verdict.accepted,
                "reason": verdict.reason.value,
                "detail": verdict.detail,
                "admin_seats": verdict.admin_seats,
                "witness_seats": verdict.witness_seats,
                "witness_roots": list(verdict.witness_roots),
            }
            decisions.append(decision)

            if verdict.accepted:
                accepted_ids.add(req.request_id)
                bucket = public_index.setdefault(
                    req.tenant, {}).setdefault(
                    req.case_id, [])
                bucket.append({
                    "request_id": req.request_id,
                    "summary_id": req.summary_id,
                    "seq": ev["seq"],
                    "bound_epoch": req.bound_epoch,
                    "witness_roots": list(verdict.witness_roots),
                })
                # 回执为重放派生：即使运行期在写回执前崩溃，也可在此恢复
                _write_json(os.path.join(
                    rcpt_dir, f"{req.request_id}.receipt.json"), {
                        "request_id": req.request_id,
                        "tenant": req.tenant,
                        "case_id": req.case_id,
                        "summary_id": req.summary_id,
                        "bound_epoch": req.bound_epoch,
                        "commit_seq": ev["seq"],
                        "witness_roots": list(verdict.witness_roots),
                        "derived_by": "replay",
                    })
            else:
                rejected_ids.add(req.request_id)
                _write_json(os.path.join(
                    q_dir, f"{req.request_id}.json"), decision)

        else:  # 未知事件类型：显式失败，不静默吞掉
            raise ValueError(f"重放遇到未知事件类型: {kind} (seq={ev['seq']})")

    # 公开索引按租户原子落盘
    for tenant, cases in public_index.items():
        for entries in cases.values():
            entries.sort(key=lambda e: e["seq"])
        _write_json(os.path.join(pub_dir, f"{tenant}.json"), cases)

    decisions_path = os.path.join(out_dir, "decisions.jsonl")
    with open(decisions_path, "w", encoding="utf-8", newline="\n") as fh:
        for d in decisions:
            fh.write(json.dumps(d, ensure_ascii=False,
                                sort_keys=True) + "\n")
        fh.flush()
        os.fsync(fh.fileno())

    # 关键不变量：失败记录绝不允许出现在任何公开索引中
    leaked = sorted(accepted_ids & rejected_ids)
    index_ids: set[str] = set()
    for cases in public_index.values():
        for entries in cases.values():
            index_ids.update(e["request_id"] for e in entries)
    leaked |= sorted(rejected_ids & index_ids)
    assert not leaked, f"失败记录泄漏进公开索引: {leaked}"

    return {
        "journal": os.path.abspath(journal_path),
        "events": len(events),
        "commits": len(decisions),
        "accepted": len(accepted_ids),
        "rejected": len(rejected_ids),
        "tenants_in_public_index": sorted(public_index),
        "quarantined": sorted(rejected_ids),
        "leaked_into_public_index": leaked,
        "decisions_path": os.path.abspath(decisions_path),
    }


def request_to_event(request: SignoffRequest) -> dict[str, Any]:
    """把签收申请转成可入日志的纯字典（枚举显式转字符串，保证可 JSON 序列化）。"""
    return {
        "request_id": request.request_id,
        "tenant": request.tenant,
        "case_id": request.case_id,
        "summary_id": request.summary_id,
        "bound_epoch": request.bound_epoch,
        "source_summary_tenant": request.source_summary_tenant,
        "seats": [{
            "pid": s.pid,
            "role": s.role.value,
            "grant_id": s.grant_id,
            "epoch": s.epoch,
        } for s in request.seats],
    }
