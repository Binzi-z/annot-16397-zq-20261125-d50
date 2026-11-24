# -*- coding: utf-8 -*-
"""Windows 原生追加日志：msvcrt 字节锁 + flush/fsync，落盘顺序即裁决顺序。

设计要点
--------
* 只使用 Python 3.12 标准库；Windows 上锁后端为 msvcrt.locking（POSIX 回退
  仅为同份代码在非 Windows 上可阅读，本次运行走 Windows 分支）。
* 每条事件一行 JSON（JSONL），写入后立即 flush + os.fsync，才分配 seq 并返回；
  seq 等于「已持久化行数」，因此 seq 的全序就是真实的落盘全序。
* 重放器只读取日志文件本身，不依赖任何内存状态——决定可重放。
"""

from __future__ import annotations

import contextlib
import json
import msvcrt  # Windows 原生：字节范围锁
import os
import time
from types import TracebackType
from typing import Any, Iterator, Optional

LOCK_TIMEOUT_SECONDS = 30.0


class LockError(RuntimeError):
    pass


class DurableJournal:
    def __init__(self, path: str) -> None:
        self.path = path
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        # a+b：每次写入定位到文件尾，与锁配合保证追加全序
        self._fh = open(path, "a+b", buffering=0)
        self._closed = False

    # ---- 原生锁 -------------------------------------------------------
    def _lock(self) -> None:
        # 锁文件首字节；LK_NBLCK 非阻塞重试，有界等待，使两个真实线程的
        # 追加在操作系统层面串行化（落盘全序由此产生）
        deadline = time.monotonic() + LOCK_TIMEOUT_SECONDS
        self._fh.seek(0)
        while True:
            try:
                msvcrt.locking(self._fh.fileno(), msvcrt.LK_NBLCK, 1)
                return
            except OSError:
                if time.monotonic() > deadline:  # pragma: no cover
                    raise LockError(
                        f"等待日志锁超时: {self.path}")
                time.sleep(0.001)
                self._fh.seek(0)

    def _unlock(self) -> None:
        self._fh.seek(0)
        try:
            msvcrt.locking(self._fh.fileno(), msvcrt.LK_UNLCK, 1)
        except OSError:  # pragma: no cover
            pass

    @contextlib.contextmanager
    def locked(self) -> Iterator[None]:
        self._lock()
        try:
            yield
        finally:
            self._unlock()

    # ---- 持久化追加 ---------------------------------------------------
    def _count_lines_locked(self) -> int:
        """用持锁句柄自身统计已持久化行数。

        不能另开句柄读取：Windows 下 msvcrt 强制锁会让其他句柄（即使同
        进程）读取被锁的首字节时触发锁定冲突；锁持有者自己的句柄可读。
        """
        self._fh.seek(0)
        n = 0
        while True:
            chunk = self._fh.read(1 << 16)
            if not chunk:
                break
            n += chunk.count(b"\n")
        return n

    def append(self, event: dict[str, Any]) -> int:
        """串行化事件并持久化，返回落盘序号 seq（从 1 开始）。"""
        with self.locked():
            # 持锁后以当前文件实际行数定 seq，杜绝两个线程拿到同号
            seq = self._count_lines_locked() + 1
            event = dict(event)
            event["seq"] = seq
            line = (json.dumps(event, ensure_ascii=False,
                               sort_keys=True) + "\n").encode("utf-8")
            self._fh.seek(0, os.SEEK_END)
            self._fh.write(line)
            self._fh.flush()
            os.fsync(self._fh.fileno())  # 强制落盘后才承认该事件
        return seq

    def read_events(self) -> list[dict[str, Any]]:
        with self.locked():
            self._fh.seek(0)
            raw = self._fh.read()
        events: list[dict[str, Any]] = []
        for line in raw.decode("utf-8").splitlines():
            if line.strip():
                events.append(json.loads(line))
        return events

    def close(self) -> None:
        if not self._closed:
            self._fh.close()
            self._closed = True

    def __enter__(self) -> "DurableJournal":
        return self

    def __exit__(
        self,
        exc_type: Optional[type[BaseException]],
        exc: Optional[BaseException],
        tb: Optional[TracebackType],
    ) -> None:
        self.close()


def read_journal(path: str) -> list[dict[str, Any]]:
    """无状态读取：重放入口，只依赖磁盘上的日志文件。"""
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]
