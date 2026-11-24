# -*- coding: utf-8 -*-
"""规则级签收案例：合格/失败签收与跨租户引用，重放后验证失败隔离。

覆盖
----
C1 alpha 合格签收（管理员 + 两个独立委托根见证人）-> 进公开索引
C2 共享源头见证人（r1 与其受托人）-> 隔离，理由 SHARED_WITNESS_ROOT
C3 beta 引用同一原始摘要且持有自有批准 -> 进 beta 的公开索引
C4 beta 无自有批准即引用 -> 隔离，理由 XREF_MISSING
C5 席位不足（只有管理员 + 一名见证人）-> 隔离，理由 SEAT_COUNT
"""

from __future__ import annotations

import json
import os
from typing import Any

from .journal import DurableJournal
from .model import RejectReason
from .replay import replay
from .synthetic import (
    CASE_A,
    CASE_B,
    SUMMARY,
    TENANT_A,
    TENANT_B,
    XREF_APPROVAL_ID,
    base_grant_events,
    commit_event,
    make_request,
    xref_approval_event,
)


def build_journal(work_dir: str) -> tuple[str, str]:
    journal_path = os.path.join(work_dir, "journal.rules.jsonl")
    if os.path.exists(journal_path):
        os.remove(journal_path)
    out_dir = os.path.join(work_dir, "out_rules")

    with DurableJournal(journal_path) as j:
        for ev in base_grant_events(TENANT_A):
            j.append(ev)
        for ev in base_grant_events(TENANT_B):
            j.append(ev)

        # C1 alpha 合格
        j.append(commit_event(make_request(
            "REQ-C1-OK", TENANT_A, CASE_A,
            ["a-admin-1", "a-wit-r1", "a-wit-r2"])))

        # C2 共享源头
        j.append(commit_event(make_request(
            "REQ-C2-SHARED", TENANT_A, CASE_A,
            ["a-admin-1", "a-wit-r1", "a-wit-r1-delegate"])))

        # C3 beta 跨租户引用 + 自有批准
        j.append(xref_approval_event(XREF_APPROVAL_ID))
        j.append(commit_event(make_request(
            "REQ-C3-XREF-OK", TENANT_B, CASE_B,
            ["b-admin-1", "b-wit-r1", "b-wit-r2"],
            source_summary_tenant=TENANT_A)))

        # C4 beta 无批准引用（另一个申请号，且不带批准——用不同 summary 使
        # 现有批准无法覆盖，模拟缺少自有批准的引用）
        j.append(commit_event(make_request(
            "REQ-C4-XREF-MISSING", TENANT_B, CASE_B,
            ["b-admin-1", "b-wit-r1", "b-wit-r2"],
            summary_id="SUMMARY-SYN-9999",
            source_summary_tenant=TENANT_A)))

        # C5 席位不足
        j.append(commit_event(make_request(
            "REQ-C5-SEATS", TENANT_A, CASE_A,
            ["a-admin-1", "a-wit-r1"])))

    return journal_path, out_dir


def run_rule_cases(work_dir: str) -> dict[str, Any]:
    journal_path, out_dir = build_journal(work_dir)
    stats = replay(journal_path, out_dir)

    with open(os.path.join(out_dir, "decisions.jsonl"),
              encoding="utf-8") as fh:
        decisions = [json.loads(line) for line in fh if line.strip()]
    by_id = {d["request_id"]: d for d in decisions}

    expected = {
        "REQ-C1-OK": (True, RejectReason.OK.value),
        "REQ-C2-SHARED": (False,
                          RejectReason.SHARED_WITNESS_ROOT.value),
        "REQ-C3-XREF-OK": (True, RejectReason.OK.value),
        "REQ-C4-XREF-MISSING": (False,
                                RejectReason.XREF_MISSING.value),
        "REQ-C5-SEATS": (False, RejectReason.SEAT_COUNT.value),
    }
    for rid, (accept, reason) in expected.items():
        d = by_id[rid]
        assert d["accepted"] is accept, rid
        assert d["reason"] == reason, (rid, d["reason"])

    # 公开索引中只能出现 C1、C3，且按租户隔离
    def index_ids(tenant_file: str) -> set[str]:
        path = os.path.join(out_dir, "public_index", tenant_file)
        if not os.path.exists(path):
            return set()
        with open(path, encoding="utf-8") as fh:
            cases = json.load(fh)
        return {e["request_id"] for entries in cases.values()
                for e in entries}

    alpha_ids = index_ids(f"{TENANT_A}.json")
    beta_ids = index_ids(f"{TENANT_B}.json")
    assert alpha_ids == {"REQ-C1-OK"}
    assert beta_ids == {"REQ-C3-XREF-OK"}

    quarantine_ids = {
        os.path.splitext(n)[0]
        for n in os.listdir(os.path.join(out_dir, "quarantine"))}
    assert quarantine_ids == {
        "REQ-C2-SHARED", "REQ-C4-XREF-MISSING", "REQ-C5-SEATS"}

    # 跨租户引用的是同一份原始摘要，但两个租户各自持有独立索引条目
    assert by_id["REQ-C1-OK"]["summary_id"] == SUMMARY
    assert by_id["REQ-C3-XREF-OK"]["summary_id"] == SUMMARY
    assert by_id["REQ-C3-XREF-OK"]["tenant"] == TENANT_B
    assert by_id["REQ-C3-XREF-OK"]["source_summary_tenant"] == TENANT_A

    return {
        "journal": os.path.abspath(journal_path),
        "replay_stats": stats,
        "decisions": decisions,
        "public_index_ids": {TENANT_A: sorted(alpha_ids),
                             TENANT_B: sorted(beta_ids)},
        "quarantine_ids": sorted(quarantine_ids),
        "isolation_assertions": {
            "failures_absent_from_public_index":
                quarantine_ids.isdisjoint(alpha_ids | beta_ids),
            "tenant_indexes_disjoint":
                alpha_ids.isdisjoint(beta_ids),
            "same_summary_separate_tenant_approvals": True,
        },
    }
