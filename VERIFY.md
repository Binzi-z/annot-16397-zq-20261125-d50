# 离线核验运行说明（原生 Windows + Python 3.12 标准库）

所有数据均为本地合成数据；程序不发起任何网络请求，仅使用标准库
（`threading`、`msvcrt`、`json`、`hashlib`、`os`、`itertools`、`random` 等）。

## 一、运行

在本目录（含 `run_all.py` 的目录）执行：

```bat
python run_all.py
```

成功时每个阶段打印 `[PASS]`，进程退出码为 0；任一断言失败退出码为 1，
失败堆栈同时写入 `evidence/summary.json` 的 `failures` 字段。

## 二、证据目录 `evidence/`

| 路径 | 含义 |
| --- | --- |
| `work/journal.*.jsonl` | 实际落盘的事件日志，每行一个事件，`seq` 即真实落盘顺序 |
| `work/out_rules/decisions.jsonl` | 可重放的逐条签收决定（含理由、见证委托根） |
| `work/out_rules/public_index/<租户>.json` | 公开索引，只含被接受的签收（按租户隔离） |
| `work/out_rules/quarantine/*.json` | 失败记录隔离区，绝不进入公开索引 |
| `work/out_*/receipts/*.receipt.json` | 重放派生回执（`derived_by=replay`），可恢复丢失回执 |
| `work/runtime_receipts_lost/` | 场景 B 中刻意不写出的运行期回执目录（应为空/不存在回执） |
| `partition_demo/partitions/tenant-*/shard-*.jsonl` | 8 租户 × 4 分片 = 60000 条合成留存记录 |
| `*.json`（顶层） | 各阶段结构化结果（含访问审计、状态机穷举、竞速轨迹） |
| `REPORT.md` | 人读核验报告 |
| `MANIFEST.sha256` | 全部证据文件的大小与 SHA-256 清单 |

## 三、题面要求与代码对应

1. 管理员 + 两名独立见证人共同签收、权限可委托、共享源头算一席、
   绑定案件/原摘要/授权代：`retention/model.py::evaluate`。
2. 另一租户引用同一原始摘要但需自有批准：`XREF_APPROVAL` 分支与
   `retention/demo_cases.py` 的 C3/C4。
3. 两个真实线程 + 屏障，按落盘顺序裁决，复现「撤销抢先」与
   「已写入承诺但未收到回执」：`retention/concurrency.py`（场景 A/B/C）。
4. 失败记录不进公开索引：`retention/replay.py` 末尾的泄漏断言，
   以及 `demo_cases.py` 的隔离区/索引集合断言。
5. 小状态机穷举短交错与共享见证：`retention/statemachine.py`。
6. 60000 条分区、局部更新不访问无关租户、比对全量结果与实际访问数：
   `retention/partition.py`（对内置 `open` 做只读计数包装）。

## 四、可重放性手工复核

删除任一 `work/out_*` 产物目录后，可对对应日志单独重放（在本目录启动
Python，确保 `retention` 包可被导入）：

```bat
python -c "from retention.replay import replay; replay(r'evidence/work/journal.rules.jsonl', r'evidence/work/out_rules_replay')"
```

重放只读取日志文件本身；新产物中的决定、公开索引、回执应与首次运行一致，
可用 `MANIFEST.sha256` 中的哈希对照（重放输出路径不同，文件内容应等价）。
