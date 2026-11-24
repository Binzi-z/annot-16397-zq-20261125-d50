# -*- coding: utf-8 -*-
"""离线核验总入口：纯 Python 3.12 标准库，全部合成数据，全程离线。

运行：python run_all.py
产物：evidence/ 目录下的实际存放文件、可重放决定、竞速轨迹、状态机穷举
报告、60000 条分区访问审计，以及 REPORT.md 与 MANIFEST.sha256。
任何断言失败都会以非零退出码结束。
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import platform
import shutil
import sys
import traceback
from datetime import datetime, timezone

from retention.concurrency import (
    run_commit_then_lost_receipt,
    run_free_contention,
    run_revoke_wins,
)
from retention.demo_cases import run_rule_cases
from retention.partition import run_partition_demo
from retention.statemachine import exhaust as fsm_exhaust


EVIDENCE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "evidence")
WORK_DIR = os.path.join(EVIDENCE_DIR, "work")
PARTITION_DIR = os.path.join(EVIDENCE_DIR, "partition_demo")


def _write_json(path: str, obj) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(obj, fh, ensure_ascii=False, indent=2, sort_keys=True)
        fh.write("\n")


def _sha256_file(path: str, buf_size: int = 1 << 16) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(buf_size), b""):
            h.update(chunk)
    return h.hexdigest()


def _build_manifest() -> list[dict[str, str]]:
    entries = []
    for root, _dirs, files in os.walk(EVIDENCE_DIR):
        for name in sorted(files):
            if name == "MANIFEST.sha256":
                continue
            path = os.path.join(root, name)
            rel = os.path.relpath(path, EVIDENCE_DIR)
            entries.append({
                "path": rel.replace(os.sep, "/"),
                "size": os.path.getsize(path),
                "sha256": _sha256_file(path),
            })
    return sorted(entries, key=lambda e: e["path"])


def _render_report(summary: dict) -> str:
    out = io.StringIO()
    w = out.write
    w("# 取证摘要签收溯源与隔离快照——离线核验报告\n\n")
    w(f"- 运行时间(UTC): {summary['run_timestamp_utc']}\n")
    w(f"- 平台: {summary['platform']}\n")
    w(f"- Python: {summary['python']}\n")
    w(f"- 数据性质: 全部为本地合成数据，无网络访问\n")
    w(f"- 总体结果: **{'全部断言通过' if summary['all_passed'] else '存在失败'}**\n\n")

    w("## 1. 规则级签收与失败隔离\n\n")
    rc = summary["rule_cases"]
    w(f"- 重放统计: {rc['replay_stats']['accepted']} 接受 / "
      f"{rc['replay_stats']['rejected']} 拒绝，"
      f"共 {rc['replay_stats']['commits']} 条签收决定\n")
    w(f"- alpha 公开索引: {rc['public_index_ids']}\n")
    w(f"- 隔离区: {rc['quarantine_ids']}\n")
    w(f"- 失败记录泄漏进公开索引: "
      f"{rc['replay_stats']['leaked_into_public_index']}\n\n")

    w("## 2. 两个真实线程 + 屏障的竞速裁决（以落盘 seq 裁决）\n\n")
    a = summary["race_revoke_wins"]
    b = summary["race_commit_no_receipt"]
    c = summary["free_contention"]
    w(f"### 场景 A 撤销抢先\n- 落盘顺序: {a['disk_order']}\n")
    w(f"- 裁决: {a['decision']['reason']} -> 隔离，无回执\n\n")
    w("### 场景 B 已写入承诺但未收到回执\n"
      f"- 落盘顺序: {b['disk_order']}\n")
    w(f"- 运行期回执存在: {b['runtime_receipt_exists']}；"
      f"重放恢复回执 derived_by={b['recovered_receipt']['derived_by']}\n\n")
    w("### 场景 C 无门控自由争用（100 轮，如实统计）\n")
    w(f"- 顺序计数: {c['order_counts']}；"
      f"两种顺序均观察到: {c['both_orders_observed']}\n\n")

    w("## 3. 小状态机短交错穷举\n\n")
    fsm = summary["fsm"]
    w(f"- 穷举短序列总数(含非法交错): {fsm['total_traces']}；"
      f"合法轨迹: {fsm['total_valid_traces']}；"
      f"非法交错: {fsm.get('total_invalid_traces', 0)}\n\n")
    for cfg in fsm["configs"]:
        w(f"- {cfg['config']}: 短序列 {cfg['short_sequences']}，"
          f"合法 {cfg['valid_traces']}，非法 {cfg['invalid_traces']}，"
          f"终态分布 {cfg['terminal_state_counts']}\n")
    w("\n")

    w("## 4. 60000 条分区记录与局部更新访问隔离\n\n")
    p = summary["partition"]
    iso = p["isolation_assertions"]
    w(f"- 生成记录: {p['generation']['records']} 条，"
      f"{p['generation']['files']} 个分片，"
      f"{p['generation']['tenants']} 个租户\n")
    w(f"- 基线全量扫描打开文件数: "
      f"{p['baseline_full_scan']['file_opens']}\n")
    w(f"- 局部更新打开文件数: "
      f"{p['partial_update']['file_opens_total']} "
      f"（仅目标租户 {p['partial_update']['updated_tenant']}）\n")
    w(f"- 更新后全量扫描打开文件数: "
      f"{p['full_scan_after_update']['file_opens']}\n")
    w(f"- 局部结果与全量结果目标租户校验和一致: "
      f"{iso['partial_matches_full_scan_target_tenant']}\n")
    w(f"- 无关租户实际访问数: "
      f"{iso['untouched_tenant_open_count']}，"
      f"明细 {iso['untouched_tenant_accesses']}\n")
    w(f"- 校验和发生变化的租户: "
      f"{[t for t, d in p['per_tenant_checksum_diff'].items() if d['changed']]}\n\n")

    w("## 5. 证据与可重放性\n\n")
    w("- 所有 JSONL 日志的 seq 即真实落盘顺序；删除 evidence/work 下的 "
      "out_* 目录后对任一 journal 重放可复现全部决定、索引与回执。\n")
    w("- MANIFEST.sha256 给出全部证据文件的大小与 SHA-256，用于完整性核验。\n")
    return out.getvalue()


def main() -> int:
    if os.path.exists(EVIDENCE_DIR):
        shutil.rmtree(EVIDENCE_DIR)
    os.makedirs(WORK_DIR, exist_ok=True)

    summary: dict = {
        "run_timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "platform": platform.platform(),
        "python": sys.version.replace("\n", " "),
        "all_passed": False,
    }
    stages = [
        ("rule_cases", lambda: run_rule_cases(WORK_DIR)),
        ("race_revoke_wins", lambda: run_revoke_wins(WORK_DIR)),
        ("race_commit_no_receipt",
         lambda: run_commit_then_lost_receipt(WORK_DIR)),
        ("free_contention", lambda: run_free_contention(WORK_DIR, 100)),
        ("fsm", fsm_exhaust),
        ("partition", lambda: run_partition_demo(PARTITION_DIR)),
    ]

    failures: list[dict[str, str]] = []
    for name, fn in stages:
        try:
            result = fn()
            summary[name] = result
            _write_json(os.path.join(EVIDENCE_DIR, f"{name}.json"), result)
            print(f"[PASS] {name}")
        except Exception:  # 记录失败证据但不让进程静默成功
            failures.append({"stage": name,
                             "traceback": traceback.format_exc()})
            print(f"[FAIL] {name}\n{traceback.format_exc()}")

    summary["failures"] = failures
    summary["all_passed"] = not failures

    report = _render_report(summary)
    with open(os.path.join(EVIDENCE_DIR, "REPORT.md"), "w",
              encoding="utf-8", newline="\n") as fh:
        fh.write(report)
    _write_json(os.path.join(EVIDENCE_DIR, "summary.json"), summary)

    manifest = _build_manifest()
    with open(os.path.join(EVIDENCE_DIR, "MANIFEST.sha256"), "w",
              encoding="utf-8", newline="\n") as fh:
        for e in manifest:
            fh.write(f"{e['sha256']}  {e['path']}  ({e['size']} bytes)\n")

    print(f"\n证据目录: {EVIDENCE_DIR}")
    print(f"清单条目: {len(manifest)} 个文件")
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
