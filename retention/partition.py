# -*- coding: utf-8 -*-
"""60000 条分区记录：验证局部更新不访问无关租户。

布局：data_dir/partitions/tenant-<n>/shard-<m>.jsonl
共 8 个租户、每租户 4 个分片、每分片 1875 条 = 60000 条合成留存记录。

访问审计
--------
对内置 open 做只读包装（builtins.open 原样保留并实际调用），记录每个被
打开文件的路径与次数，形成「实际访问数」证据，而不是凭设计推断。

两种工作负载并比对
------------------
1. 全量扫描：读取全部分区，重算每租户校验和与总校验和；
2. 局部更新：只更新一个租户的一条记录，仅打开该租户的分片，
   重算结果必须与「更新后再做一次全量扫描」逐租户一致；
   且审计必须证明其余 7 个租户的文件访问数为 0。
"""

from __future__ import annotations

import builtins
import hashlib
import json
import os
import random
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any

TENANT_COUNT = 8
SHARDS_PER_TENANT = 4
RECORDS_PER_TENANT = 7500
TOTAL_RECORDS = TENANT_COUNT * RECORDS_PER_TENANT  # 60000
TARGET_TENANT = "tenant-3"

_real_open = builtins.open


@dataclass
class AccessAudit:
    counts: dict[str, int] = field(default_factory=dict)

    def record(self, path: str) -> None:
        norm = os.path.normcase(os.path.abspath(path))
        self.counts[norm] = self.counts.get(norm, 0) + 1

    def total(self) -> int:
        return sum(self.counts.values())

    def by_tenant(self, partition_dir: str) -> dict[str, int]:
        out: dict[str, int] = {}
        base = os.path.normcase(os.path.abspath(partition_dir))
        for path, n in self.counts.items():
            if path.startswith(base + os.sep):
                rel = os.path.relpath(path, base)
                tenant = rel.split(os.sep)[0]
                out[tenant] = out.get(tenant, 0) + n
        return dict(sorted(out.items()))


@contextmanager
def audited_open(audit: AccessAudit):
    """临时安装带访问计数的 open；退出时恢复 builtins.open。"""

    def tracked_open(file, mode="r", *args, **kwargs):
        # 只审计真实文件系统路径；StringIO 等不走这里
        if isinstance(file, (str, bytes, os.PathLike)):
            audit.record(os.fspath(file))
        return _real_open(file, mode, *args, **kwargs)

    builtins.open = tracked_open  # type: ignore[assignment]
    try:
        yield
    finally:
        builtins.open = _real_open  # type: ignore[assignment]


# ----------------------------------------------------------------------
# 合成数据生成（确定性随机种子，可重复生成同一份 60000 条）
# ----------------------------------------------------------------------
def generate_partitions(data_dir: str) -> dict[str, Any]:
    partition_dir = os.path.join(data_dir, "partitions")
    rng = random.Random(20261125)
    per_shard = RECORDS_PER_TENANT // SHARDS_PER_TENANT  # 1875
    written = 0
    files: list[str] = []

    for t in range(TENANT_COUNT):
        tenant = f"tenant-{t}"
        tdir = os.path.join(partition_dir, tenant)
        os.makedirs(tdir, exist_ok=True)
        for s in range(SHARDS_PER_TENANT):
            path = os.path.join(tdir, f"shard-{s}.jsonl")
            with _real_open(path, "w", encoding="utf-8",
                            newline="\n") as fh:
                for i in range(per_shard):
                    rec_id = f"{tenant}-r{s * per_shard + i:05d}"
                    rec = {
                        "record_id": rec_id,
                        "tenant": tenant,
                        "case_id": f"{tenant.upper()}-CASE-{i % 97:03d}",
                        "summary_id": f"SYN-SUM-{rng.randint(1000, 9999)}",
                        "retention_class": rng.choice(
                            ["std-3y", "long-7y", "legal-hold"]),
                        "payload_hash": hashlib.sha256(
                            f"{rec_id}|{rng.random()}".encode()
                        ).hexdigest()[:32],
                        "status": "active",
                    }
                    fh.write(json.dumps(rec, ensure_ascii=False,
                                        sort_keys=True) + "\n")
                    written += 1
            files.append(os.path.abspath(path))

    assert written == TOTAL_RECORDS
    return {"partition_dir": os.path.abspath(partition_dir),
            "records": written, "files": len(files),
            "tenants": TENANT_COUNT,
            "shards_per_tenant": SHARDS_PER_TENANT}


def _tenant_shards(partition_dir: str, tenant: str) -> list[str]:
    tdir = os.path.join(partition_dir, tenant)
    return sorted(
        os.path.join(tdir, n) for n in os.listdir(tdir)
        if n.endswith(".jsonl"))


def _all_shards(partition_dir: str) -> list[str]:
    paths: list[str] = []
    for tenant in sorted(os.listdir(partition_dir)):
        tdir = os.path.join(partition_dir, tenant)
        if os.path.isdir(tdir):
            paths.extend(_tenant_shards(partition_dir, tenant))
    return sorted(paths)


def _checksum_records(paths: list[str]) -> tuple[str, dict[str, str], int]:
    """读取给定分片，返回总校验和、每租户校验和与记录数。"""
    total = hashlib.sha256()
    per_tenant: dict[str, hashlib._Hash] = {}
    count = 0
    for path in paths:
        tenant = os.path.basename(os.path.dirname(path))
        h = per_tenant.setdefault(tenant, hashlib.sha256())
        with open(path, "r", encoding="utf-8") as fh:  # 被审计的 open
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                total.update(line.encode("utf-8"))
                h.update(line.encode("utf-8"))
                count += 1
    return (total.hexdigest(),
            {k: v.hexdigest() for k, v in sorted(per_tenant.items())},
            count)


def full_scan(partition_dir: str, audit: AccessAudit
              ) -> dict[str, Any]:
    with audited_open(audit):
        checksum, per_tenant, count = _checksum_records(
            _all_shards(partition_dir))
    return {"checksum": checksum, "per_tenant": per_tenant,
            "record_count": count, "file_opens": audit.total()}


def partial_update(partition_dir: str, audit: AccessAudit,
                   tenant: str, record_id: str,
                   new_status: str = "hold") -> dict[str, Any]:
    """只更新指定租户的一条记录；只允许打开该租户名下的分片。"""
    touched: list[str] = []
    with audited_open(audit):
        for path in _tenant_shards(partition_dir, tenant):
            changed = False
            rows: list[dict[str, Any]] = []
            with open(path, "r", encoding="utf-8") as fh:
                for line in fh:
                    if not line.strip():
                        continue
                    rec = json.loads(line)
                    if rec["record_id"] == record_id:
                        rec["status"] = new_status
                        changed = True
                    rows.append(rec)
            if changed:
                tmp = path + ".tmp"
                with open(tmp, "w", encoding="utf-8",
                          newline="\n") as fh:
                    for rec in rows:
                        fh.write(json.dumps(
                            rec, ensure_ascii=False,
                            sort_keys=True) + "\n")
                os.replace(tmp, path)
                touched.append(os.path.abspath(path))

        checksum, per_tenant, count = _checksum_records(
            _tenant_shards(partition_dir, tenant))

    by_tenant = audit.by_tenant(partition_dir)
    return {
        "updated_tenant": tenant,
        "updated_record": record_id,
        "touched_shards": touched,
        "tenant_checksum_after": checksum,
        "per_tenant_checksum_after": per_tenant,
        "tenant_record_count": count,
        "file_opens_total": audit.total(),
        "file_opens_by_tenant": by_tenant,
    }


def run_partition_demo(data_dir: str) -> dict[str, Any]:
    gen = generate_partitions(data_dir)
    partition_dir = gen["partition_dir"]

    # 基线全量扫描
    base_audit = AccessAudit()
    baseline = full_scan(partition_dir, base_audit)

    # 局部更新（目标租户的一条记录）
    target_record = f"{TARGET_TENANT}-r00042"
    upd_audit = AccessAudit()
    updated = partial_update(partition_dir, upd_audit,
                             TARGET_TENANT, target_record)

    # 更新后再做一次全量扫描，作为比对基准
    after_audit = AccessAudit()
    after_full = full_scan(partition_dir, after_audit)

    # 局部更新仅重算目标租户；把它与更新后全量结果中的目标租户比对
    partial_tenant_checksum = updated["tenant_checksum_after"]
    full_target_checksum = after_full["per_tenant"][TARGET_TENANT]

    untouched = {
        t: n for t, n in updated["file_opens_by_tenant"].items()
        if t != TARGET_TENANT}
    target_opens = updated["file_opens_by_tenant"].get(TARGET_TENANT, 0)

    # 校验和差异：除目标租户外，其他租户校验和必须与基线完全一致
    per_tenant_diff = {
        t: {"baseline": baseline["per_tenant"][t],
            "after_full_scan": after_full["per_tenant"][t],
            "changed": baseline["per_tenant"][t]
            != after_full["per_tenant"][t]}
        for t in sorted(baseline["per_tenant"])
    }
    changed_tenants = sorted(
        t for t, d in per_tenant_diff.items() if d["changed"])

    assert baseline["record_count"] == TOTAL_RECORDS
    assert after_full["record_count"] == TOTAL_RECORDS
    assert partial_tenant_checksum == full_target_checksum
    assert changed_tenants == [TARGET_TENANT]
    assert untouched == {}, f"局部更新访问了无关租户: {untouched}"
    assert target_opens > 0
    # 局部更新打开数应远小于全量扫描（目标租户 4 个分片的读写量级）
    assert updated["file_opens_total"] < after_audit.total()

    return {
        "generation": gen,
        "baseline_full_scan": {
            "checksum": baseline["checksum"],
            "record_count": baseline["record_count"],
            "file_opens": baseline["file_opens"],
        },
        "partial_update": updated,
        "full_scan_after_update": {
            "checksum": after_full["checksum"],
            "record_count": after_full["record_count"],
            "file_opens": after_full["file_opens"],
        },
        "per_tenant_checksum_diff": per_tenant_diff,
        "isolation_assertions": {
            "partial_matches_full_scan_target_tenant":
                partial_tenant_checksum == full_target_checksum,
            "only_target_tenant_checksum_changed":
                changed_tenants == [TARGET_TENANT],
            "untouched_tenant_accesses": untouched,
            "untouched_tenant_open_count": sum(untouched.values()),
            "target_tenant_open_count": target_opens,
            "full_scan_open_count": after_audit.total(),
            "partial_update_opened_fewer_files":
                updated["file_opens_total"] < after_audit.total(),
        },
    }
