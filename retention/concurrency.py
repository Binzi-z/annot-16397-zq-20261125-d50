# -*- coding: utf-8 -*-
"""两个真实线程的签收竞速：入档线程 vs 权限撤销线程。

线程身份与同步原语
------------------
* threading.Barrier(2)：两个线程都到达同一栅栏后才允许继续，保证它们
  是在同一起点上争用落盘顺序，而不是因为启动先后伪竞速；
* threading.Event 门控：用于把两种题面要求的交错「可复现」地固定下来；
* 落盘顺序以 DurableJournal 的 seq 为唯一裁决依据。

两个被复现的交错
----------------
A. 撤销抢先（revoke_first）：REVOKE 的 seq 小于 COMMIT 的 seq。
   提交时仍绑定旧授权代 -> 重放裁决为 STALE_EPOCH，承诺进隔离区，
   不产生公开索引条目，也不产生回执。
B. 已写入承诺但未收到回执（commit_first_receipt_lost）：COMMIT 先落盘，
   入档线程在「写运行期回执」这一步之前被门控阻断（模拟进程崩溃/回执丢失）。
   重放依据日志重新派生出回执（derived_by=replay），签收仍然成立。

另跑无门控自由争用多轮，统计两种落盘顺序的真实出现情况（不预设结果）。
"""

from __future__ import annotations

import json
import os
import threading
from dataclasses import dataclass
from typing import Any

from .journal import DurableJournal, read_journal
from .model import RejectReason
from .replay import replay
from .synthetic import (
    EPOCH_AFTER_REVOKE,
    EPOCH_INITIAL,
    TENANT_A,
    CASE_A,
    base_grant_events,
    commit_event,
    make_request,
    revoke_event,
    with_stale_epoch,
)


@dataclass
class ThreadTrace:
    name: str
    ident: int
    actions: list[dict[str, Any]]


def _log_action(trace: ThreadTrace, action: str, **extra: Any) -> None:
    trace.actions.append({"action": action, **extra})


def _seed_grants(journal: DurableJournal) -> None:
    for ev in base_grant_events(TENANT_A):
        journal.append(ev)


def _write_runtime_receipt(receipt_dir: str, request_id: str,
                           seq: int) -> str:
    """运行期回执（与重放派生回执区分开）。"""
    os.makedirs(receipt_dir, exist_ok=True)
    path = os.path.join(receipt_dir, f"{request_id}.receipt.json")
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump({"request_id": request_id, "runtime_commit_seq": seq,
                   "derived_by": "runtime"}, fh, ensure_ascii=False,
                  sort_keys=True, indent=2)
        fh.write("\n")
        fh.flush()
        os.fsync(fh.fileno())
    return path


# ----------------------------------------------------------------------
# 场景 A：撤销抢先（屏障 + 门控，确定性复现）
# ----------------------------------------------------------------------
def run_revoke_wins(work_dir: str) -> dict[str, Any]:
    journal_path = os.path.join(work_dir, "journal.revoke_wins.jsonl")
    if os.path.exists(journal_path):
        os.remove(journal_path)

    barrier = threading.Barrier(2)
    revoker_release = threading.Event()   # 撤销线程先过
    archiver_release = threading.Event()  # 撤销落盘后才放行入档
    traces: list[ThreadTrace] = []

    req = with_stale_epoch(
        make_request("REQ-RACE-A", TENANT_A, CASE_A,
                     ["a-admin-1", "a-wit-r1", "a-wit-r2"]),
        EPOCH_INITIAL)

    # 先播种初始授权（epoch=1），再让两个真实线程在同屏障上争用
    with DurableJournal(journal_path) as seed:
        _seed_grants(seed)

    def revoker() -> None:
        trace = ThreadTrace("revoker", threading.get_ident(), [])
        traces.append(trace)
        with DurableJournal(journal_path) as j:
            barrier.wait()                 # 与入档线程同一起点
            revoker_release.wait()
            seq = j.append(revoke_event("g-a-wit-r1", EPOCH_AFTER_REVOKE))
            _log_action(trace, "append_revoke", seq=seq,
                        revoke_epoch=EPOCH_AFTER_REVOKE)
            archiver_release.set()

    def archiver() -> None:
        trace = ThreadTrace("archiver", threading.get_ident(), [])
        traces.append(trace)
        with DurableJournal(journal_path) as j:
            barrier.wait()
            revoker_release.set()
            archiver_release.wait()        # 确保撤销已落盘
            seq = j.append(commit_event(req))
            _log_action(trace, "append_commit", seq=seq,
                        bound_epoch=req.bound_epoch)

    t1 = threading.Thread(target=revoker, name="revoker-thread")
    t2 = threading.Thread(target=archiver, name="archiver-thread")
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    events = read_journal(journal_path)
    order = [e["kind"] for e in events if e["kind"] in ("REVOKE", "COMMIT")]
    out_dir = os.path.join(work_dir, "out_revoke_wins")
    stats = replay(journal_path, out_dir)

    decisions = [json.loads(line) for line in open(
        os.path.join(out_dir, "decisions.jsonl"), encoding="utf-8")]
    decision = decisions[0]
    assert order == ["REVOKE", "COMMIT"], order
    assert decision["accepted"] is False
    assert decision["reason"] == RejectReason.STALE_EPOCH.value
    assert not os.path.exists(
        os.path.join(out_dir, "receipts", "REQ-RACE-A.receipt.json"))
    assert os.path.exists(
        os.path.join(out_dir, "quarantine", "REQ-RACE-A.json"))

    return {
        "scenario": "A_revoke_wins",
        "journal": os.path.abspath(journal_path),
        "disk_order": order,
        "thread_traces": [t.__dict__ for t in traces],
        "decision": decision,
        "replay_stats": stats,
        "assertions": {
            "revoke_seq_before_commit_seq": True,
            "committed_into_quarantine": True,
            "no_receipt_issued": True,
            "absent_from_public_index":
                "REQ-RACE-A" not in json.dumps(
                    list(_walk_public_index(out_dir))),
        },
    }


# ----------------------------------------------------------------------
# 场景 B：承诺已落盘，但运行期回执未送达（屏障 + 门控，确定性复现）
# ----------------------------------------------------------------------
def run_commit_then_lost_receipt(work_dir: str) -> dict[str, Any]:
    journal_path = os.path.join(work_dir,
                                "journal.commit_no_receipt.jsonl")
    if os.path.exists(journal_path):
        os.remove(journal_path)

    barrier = threading.Barrier(2)
    archiver_release = threading.Event()
    block_receipt = threading.Event()     # 置位 => 模拟回执通道中断
    receipt_allowed = threading.Event()
    traces: list[ThreadTrace] = []
    runtime_receipt_dir = os.path.join(work_dir, "runtime_receipts_lost")

    req = make_request("REQ-RACE-B", TENANT_A, CASE_A,
                       ["a-admin-1", "a-wit-r1", "a-wit-r2"])

    with DurableJournal(journal_path) as seed:
        _seed_grants(seed)

    def archiver() -> None:
        trace = ThreadTrace("archiver", threading.get_ident(), [])
        traces.append(trace)
        with DurableJournal(journal_path) as j:
            barrier.wait()
            archiver_release.wait()
            seq = j.append(commit_event(req))
            _log_action(trace, "append_commit", seq=seq)
            block_receipt.wait()         # 模拟在写回执前崩溃/断链
            if receipt_allowed.is_set():
                path = _write_runtime_receipt(
                    runtime_receipt_dir, req.request_id, seq)
                _log_action(trace, "runtime_receipt_written", path=path)
            else:
                _log_action(trace, "runtime_receipt_abandoned",
                            note="承诺已持久化，回执未送达")

    def revoker() -> None:
        trace = ThreadTrace("revoker", threading.get_ident(), [])
        traces.append(trace)
        with DurableJournal(journal_path) as j:
            barrier.wait()
            archiver_release.set()       # 放行入档；本线程不撤销
            _log_action(trace, "stand_down",
                        note="本轮不撤销，仅与入档线程同屏障对齐")

    t1 = threading.Thread(target=archiver, name="archiver-thread")
    t2 = threading.Thread(target=revoker, name="revoker-thread")
    t1.start()
    t2.start()
    t2.join()
    block_receipt.set()   # 让入档线程越过等待点，但永不允许写运行期回执
    t1.join()

    events = read_journal(journal_path)
    order = [e["kind"] for e in events if e["kind"] in ("REVOKE", "COMMIT")]
    assert order == ["COMMIT"], order
    assert not os.path.exists(os.path.join(
        runtime_receipt_dir, "REQ-RACE-B.receipt.json"))

    out_dir = os.path.join(work_dir, "out_commit_no_receipt")
    stats = replay(journal_path, out_dir)
    recovered = os.path.join(out_dir, "receipts",
                             "REQ-RACE-B.receipt.json")
    assert os.path.exists(recovered)
    with open(recovered, encoding="utf-8") as fh:
        receipt = json.load(fh)
    assert receipt["derived_by"] == "replay"

    return {
        "scenario": "B_commit_persisted_receipt_lost",
        "journal": os.path.abspath(journal_path),
        "disk_order": order,
        "thread_traces": [t.__dict__ for t in traces],
        "recovered_receipt": receipt,
        "runtime_receipt_exists": False,
        "replay_stats": stats,
        "assertions": {
            "commit_persisted_before_failure": True,
            "runtime_receipt_never_written": True,
            "receipt_recovered_by_replay": True,
            "present_in_public_index":
                "REQ-RACE-B" in json.dumps(
                    list(_walk_public_index(out_dir))),
        },
    }


# ----------------------------------------------------------------------
# 无门控自由争用：多轮统计两种真实落盘顺序（如实记录，不保证一定都出现）
# ----------------------------------------------------------------------
def run_free_contention(work_dir: str, rounds: int = 100) -> dict[str, Any]:
    journal_path = os.path.join(work_dir, "journal.free_contention.jsonl")
    if os.path.exists(journal_path):
        os.remove(journal_path)
    # 先播种真实初始授权，使日志在语义上可被重放器完整解释
    with DurableJournal(journal_path) as seed:
        _seed_grants(seed)

    barrier = threading.Barrier(2)
    counts = {"REVOKE_first": 0, "COMMIT_first": 0}
    round_orders: list[list[str]] = []

    def revoker(round_idx: int) -> None:
        barrier.wait()
        with DurableJournal(journal_path) as j:
            # 每轮对同一条真实授权发起撤销（重复撤销在重放映射中幂等）
            j.append(revoke_event("g-a-wit-r1", EPOCH_AFTER_REVOKE))

    def archiver(round_idx: int) -> None:
        req = make_request(f"REQ-FREE-{round_idx}", TENANT_A, CASE_A,
                           ["a-admin-1", "a-wit-r1", "a-wit-r2"])
        barrier.wait()
        with DurableJournal(journal_path) as j:
            j.append(commit_event(req))

    for r in range(rounds):
        t1 = threading.Thread(target=revoker, args=(r,))
        t2 = threading.Thread(target=archiver, args=(r,))
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        kinds = [e["kind"] for e in read_journal(journal_path)
                 if e["kind"] in ("REVOKE", "COMMIT")]
        # 每轮恰好新增一条 REVOKE 与一条 COMMIT，取最后两条的相对顺序
        pair = kinds[-2:]
        assert set(pair) == {"REVOKE", "COMMIT"}, pair
        round_orders.append(pair)
        if pair[0] == "REVOKE":
            counts["REVOKE_first"] += 1
        else:
            counts["COMMIT_first"] += 1

    assert counts["REVOKE_first"] + counts["COMMIT_first"] == rounds
    return {
        "scenario": "C_free_contention",
        "rounds": rounds,
        "order_counts": counts,
        "both_orders_observed": all(v > 0 for v in counts.values()),
        "sample_orders": round_orders[:10],
    }


def _walk_public_index(out_dir: str):
    idx = os.path.join(out_dir, "public_index")
    for name in sorted(os.listdir(idx)):
        with open(os.path.join(idx, name), encoding="utf-8") as fh:
            yield json.load(fh)
