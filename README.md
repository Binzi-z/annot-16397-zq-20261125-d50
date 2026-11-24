# 取证摘要的签收溯源与隔离快照

获确认的题面位于 task/PROMPT.txt。使用原生 Windows 和标准库，输入与验证使用本地合成数据。

## 运行

```bat
python run_all.py
```

成功时各阶段打印 `[PASS]`、退出码 0，证据写入 `evidence/`（含 REPORT.md 与
MANIFEST.sha256）。详细核验步骤见 [VERIFY.md](VERIFY.md)。

## 模块

- `retention/model.py`：纯函数签收规则（委托链、授权代、共享源头见证、跨租户批准）
- `retention/journal.py`：msvcrt 字节锁 + fsync 的 JSONL 追加日志，seq 即落盘顺序
- `retention/replay.py`：只读日志的无状态重放裁决（决定/公开索引/隔离区/回执）
- `retention/concurrency.py`：两个真实线程 + Barrier 的撤销抢先与回执丢失场景
- `retention/statemachine.py`：签收生命周期小状态机与短交错穷举
- `retention/partition.py`：60000 条分区记录与局部更新的访问隔离审计
- `retention/demo_cases.py` / `retention/synthetic.py`：规则案例与合成数据

