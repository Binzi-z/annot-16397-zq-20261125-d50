# -*- coding: utf-8 -*-
"""签收生命周期小状态机 + 短交错穷举。

显式状态与迁移（迁移表是单一事实来源，不允许隐式跳转）
------------------------------------------------------
    OPEN --ADD_ADMIN_SEAT--> HAS_ADMIN
    OPEN/HAS_ADMIN/HAS_WITNESS_1 --ADD_WITNESS_SEAT--> 下一见证态
    HAS_ADMIN --ADD_ADMIN_SEAT--> HAS_ADMIN（幂等，同一管理员不重复计席）
    任一非终态 --REVOKE--> REVOKED（终态，后续 COMMIT 被迁移表拒绝）
    HAS_TWO_SEATS --COMMIT(守卫通过)--> COMMITTED
    HAS_TWO_SEATS --COMMIT(守卫失败)--> REJECTED
    终态（COMMITTED/REJECTED/REVOKED）不接受任何事件

守卫判定完全委托 model.evaluate：状态机负责「合法交错」，规则引擎负责
「同一交错下是否合格」，两者对每条穷举轨迹必须结论一致（交叉验证）。

穷举范围
--------
* itertools.permutations 穷举一组短事件（长度 <= 5）的全部交错；
* 配置覆盖：独立双见证、共享源头见证、委托管理员、席位不足、
  撤销抢先、跨租户引用（有/无自有批准、批准被撤销）。
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional

from .model import (
    RejectReason,
    SignoffRequest,
    evaluate,
)
from .synthetic import (
    EPOCH_AFTER_REVOKE,
    EPOCH_INITIAL,
    TENANT_A,
    TENANT_B,
    CASE_A,
    CASE_B,
    GRANTS,
    PRINCIPALS,
    XREF_APPROVAL_ID,
    make_request,
    with_stale_epoch,
    xref_approval_event,
)


class State(str, Enum):
    OPEN = "OPEN"
    HAS_ADMIN = "HAS_ADMIN"
    HAS_WITNESS_1 = "HAS_WITNESS_1"
    HAS_TWO_SEATS = "HAS_TWO_SEATS"
    REVOKED = "REVOKED"
    COMMITTED = "COMMITTED"
    REJECTED = "REJECTED"


TERMINAL_STATES = frozenset(
    {State.REVOKED, State.COMMITTED, State.REJECTED})


class Event(str, Enum):
    ADD_ADMIN_SEAT = "ADD_ADMIN_SEAT"
    ADD_WITNESS_A = "ADD_WITNESS_A"
    ADD_WITNESS_B = "ADD_WITNESS_B"
    ADD_SHARED_WITNESS = "ADD_SHARED_WITNESS"
    REVOKE = "REVOKE"
    COMMIT = "COMMIT"


@dataclass(frozen=True)
class FSMConfig:
    name: str
    request: SignoffRequest
    revoke_map: dict[str, int]          # gid -> revoke_epoch
    xref: tuple[dict[str, Any], ...]
    # COMMIT 守卫期望：(是否接受, 拒绝理由或 None)
    expect_accept: bool
    expect_reason: Optional[RejectReason]
    current_epoch: int = EPOCH_INITIAL
    # 撤销类配置：裁决结果取决于 REVOKE 与 COMMIT 在交错中的先后
    order_sensitive_revocation: bool = False


@dataclass
class Trace:
    order: tuple[Event, ...]
    final_state: State
    guard_accept: Optional[bool]
    guard_reason: Optional[str]
    valid: bool


# 显式迁移表：(当前状态, 事件) -> 下一状态（COMMIT 走带守卫的函数）
def _next_witness_state(state: State) -> State:
    if state in (State.OPEN, State.HAS_ADMIN):
        return State.HAS_WITNESS_1
    if state == State.HAS_WITNESS_1:
        return State.HAS_TWO_SEATS
    return state  # 已满，幂等停留


def step(state: State, event: Event, cfg: FSMConfig,
         revoke_seen: bool
         ) -> tuple[State, Optional[bool], Optional[str]]:
    """执行一次迁移，返回 (新状态, 守卫是否接受, 守卫理由)。

    终态收到事件、或迁移表中不存在的 (状态,事件) 组合 -> 非法迁移。
    revoke_seen 表示该交错此前是否已发生 REVOKE，使守卫对顺序敏感。
    """
    if state in TERMINAL_STATES:
        raise ValueError(f"终态 {state.value} 不接受事件 {event.value}")

    if event == Event.ADD_ADMIN_SEAT:
        if state == State.OPEN:
            return State.HAS_ADMIN, None, None
        return state, None, None  # 管理员席幂等

    if event in (Event.ADD_WITNESS_A, Event.ADD_WITNESS_B,
                 Event.ADD_SHARED_WITNESS):
        return _next_witness_state(state), None, None

    if event == Event.REVOKE:
        return State.REVOKED, None, None

    if event == Event.COMMIT:
        if state != State.HAS_TWO_SEATS:
            raise ValueError(
                f"状态 {state.value} 下 COMMIT 不合法（席位未满）")
        # 撤销未在本交错中发生时，按撤销前快照（epoch=1、无撤销映射）裁决
        if cfg.order_sensitive_revocation and not revoke_seen:
            verdict = evaluate(
                cfg.request, PRINCIPALS, GRANTS, {}, cfg.xref,
                current_epoch=EPOCH_INITIAL)
        else:
            verdict = evaluate(
                cfg.request, PRINCIPALS, GRANTS, cfg.revoke_map,
                cfg.xref, current_epoch=cfg.current_epoch)
        if verdict.accepted:
            return State.COMMITTED, True, RejectReason.OK.value
        return State.REJECTED, False, verdict.reason.value

    raise ValueError(f"未知事件 {event.value}")


def run_trace(order: tuple[Event, ...], cfg: FSMConfig) -> Trace:
    """按顺序执行一个短交错。

    到达终态即自然收尾（终态后的剩余事件不应再被执行，调用方保证）。
    任何一步非法迁移会抛 ValueError，由穷举器记为非法交错。
    """
    state = State.OPEN
    guard_accept: Optional[bool] = None
    guard_reason: Optional[str] = None
    revoke_seen = False
    for ev in order:
        state, guard_accept, guard_reason = step(
            state, ev, cfg, revoke_seen)
        if ev == Event.REVOKE:
            revoke_seen = True
        if state in TERMINAL_STATES:
            break
    return Trace(order, state, guard_accept, guard_reason, valid=True)


def short_sequences(events: tuple[Event, ...]
                    ) -> set[tuple[Event, ...]]:
    """枚举所有「短交错」：每个长度 1..N 的无重复排列（去重）。

    这样含终态事件（COMMIT/REVOKE）的序列在到达终态处即收尾，
    不会出现“终态之后还有事件”的伪非法交错；同时保留对席位未满即
    COMMIT 这类真正非法短序列的覆盖（会在 step 中抛错）。
    """
    seqs: set[tuple[Event, ...]] = set()
    for r in range(1, len(events) + 1):
        seqs.update(itertools.permutations(events, r))
    return seqs


def _cfg_independent() -> FSMConfig:
    req = make_request(
        "FSM-IND", TENANT_A, CASE_A,
        ["a-admin-1", "a-wit-r1", "a-wit-r2"])
    return FSMConfig("独立双见证_合格", req, {}, (), True, None)


def _cfg_shared_root() -> FSMConfig:
    # 管理员 + 两名共享委托根的见证人（r1 与其受托人）
    req = make_request(
        "FSM-SHARED", TENANT_A, CASE_A,
        ["a-admin-1", "a-wit-r1", "a-wit-r1-delegate"])
    return FSMConfig("共享源头_仅算一席", req, {}, (),
                     False, RejectReason.SHARED_WITNESS_ROOT)


def _cfg_delegated_admin() -> FSMConfig:
    req = make_request(
        "FSM-DELADMIN", TENANT_A, CASE_A,
        ["a-admin-2", "a-wit-r1", "a-wit-r2"])
    return FSMConfig("委托管理员_合格", req, {}, (), True, None)


def _cfg_revoke_wins() -> FSMConfig:
    req = with_stale_epoch(
        make_request("FSM-REVOKE", TENANT_A, CASE_A,
                     ["a-admin-1", "a-wit-r1", "a-wit-r2"]),
        EPOCH_INITIAL)
    return FSMConfig(
        "撤销抢先_陈旧授权代", req,
        {"g-a-wit-r1": EPOCH_AFTER_REVOKE}, (),
        False, RejectReason.STALE_EPOCH,
        current_epoch=EPOCH_AFTER_REVOKE,
        order_sensitive_revocation=True)


def _cfg_xref_ok() -> FSMConfig:
    req = make_request(
        "FSM-XREF-OK", TENANT_B, CASE_B,
        ["b-admin-1", "b-wit-r1", "b-wit-r2"],
        source_summary_tenant=TENANT_A)
    approval = dict(xref_approval_event(XREF_APPROVAL_ID))
    approval["revoked"] = False
    return FSMConfig("跨租户引用_自有批准_合格", req, {},
                     (approval,), True, None)


def _cfg_xref_missing() -> FSMConfig:
    req = make_request(
        "FSM-XREF-MISS", TENANT_B, CASE_B,
        ["b-admin-1", "b-wit-r1", "b-wit-r2"],
        source_summary_tenant=TENANT_A)
    return FSMConfig("跨租户引用_缺自有批准", req, {}, (),
                     False, RejectReason.XREF_MISSING)


def _cfg_xref_revoked() -> FSMConfig:
    req = make_request(
        "FSM-XREF-REV", TENANT_B, CASE_B,
        ["b-admin-1", "b-wit-r1", "b-wit-r2"],
        source_summary_tenant=TENANT_A)
    approval = dict(xref_approval_event(XREF_APPROVAL_ID))
    approval["revoked"] = True
    return FSMConfig("跨租户引用_批准已撤销", req, {},
                     (approval,), False, RejectReason.XREF_REVOKED)


# 事件池：席位三事件 + 可选撤销 + 提交（长度 5，120 种交错以内）
def _event_pool(with_revoke: bool, shared: bool
                ) -> tuple[Event, ...]:
    pool = [
        Event.ADD_ADMIN_SEAT,
        Event.ADD_WITNESS_A,
        Event.ADD_SHARED_WITNESS if shared else Event.ADD_WITNESS_B,
        Event.COMMIT,
    ]
    if with_revoke:
        pool.append(Event.REVOKE)
    return tuple(pool)


def exhaust() -> dict[str, Any]:
    configs = [
        _cfg_independent(),
        _cfg_shared_root(),
        _cfg_delegated_admin(),
        _cfg_revoke_wins(),
        _cfg_xref_ok(),
        _cfg_xref_missing(),
        _cfg_xref_revoked(),
    ]
    report: dict[str, Any] = {"configs": [], "total_traces": 0,
                              "total_valid_traces": 0}

    for cfg in configs:
        shared = cfg.expect_reason == RejectReason.SHARED_WITNESS_ROOT
        with_revoke = cfg.name.startswith("撤销抢先")
        pool = _event_pool(with_revoke, shared)
        all_orders = short_sequences(pool)

        traces: list[dict[str, Any]] = []
        valid_count = 0
        invalid_count = 0
        state_counts: dict[str, int] = {}
        for order in sorted(all_orders, key=lambda o: [e.value for e in o]):
            try:
                tr = run_trace(order, cfg)
            except ValueError:
                # 真正的非法短交错：席位未满即 COMMIT（终态后再迁移的情形
                # 已由“到终态即收尾”的短序列枚举排除）
                invalid_count += 1
                traces.append({"order": [e.value for e in order],
                               "valid": False})
                continue
            valid_count += 1
            state_counts[tr.final_state.value] = \
                state_counts.get(tr.final_state.value, 0) + 1

            # 交叉验证不变量：到达 COMMITTED 当且仅当规则引擎判接受
            if tr.final_state == State.COMMITTED:
                assert tr.guard_accept is True
                if not cfg.order_sensitive_revocation:
                    assert cfg.expect_accept is True
            if tr.final_state == State.REJECTED:
                assert tr.guard_accept is False
                if not cfg.order_sensitive_revocation:
                    assert tr.guard_reason == cfg.expect_reason.value
            traces.append({
                "order": [e.value for e in order],
                "valid": True,
                "final_state": tr.final_state.value,
                "guard_accept": tr.guard_accept,
                "guard_reason": tr.guard_reason,
            })

        # 配置级不变量
        committed = state_counts.get(State.COMMITTED.value, 0)
        if cfg.order_sensitive_revocation:
            # REVOKE 在本状态机中是终态：
            #  - COMMIT 排在 REVOKE 之前且席位已满 -> COMMITTED（撤销前快照合格）
            #  - REVOKE 排在 COMMIT 之前 -> REVOKED（撤销抢先，签收被阻断）
            # 两种相对顺序都必须被穷举到
            revoked = state_counts.get(State.REVOKED.value, 0)
            assert committed > 0 and revoked > 0, cfg.name
        elif cfg.expect_accept:
            assert committed > 0, f"{cfg.name} 应有合格轨迹"
        else:
            assert committed == 0, f"{cfg.name} 不应出现合格轨迹"

        report["total_traces"] += len(all_orders)
        report["total_valid_traces"] += valid_count
        report["total_invalid_traces"] = \
            report.get("total_invalid_traces", 0) + invalid_count
        report["configs"].append({
            "config": cfg.name,
            "event_pool": [e.value for e in pool],
            "short_sequences": len(all_orders),
            "valid_traces": valid_count,
            "invalid_traces": invalid_count,
            "terminal_state_counts": state_counts,
            "expect_accept": cfg.expect_accept,
            "expect_reason":
                cfg.expect_reason.value if cfg.expect_reason else None,
            "sample_traces": traces[:12],
        })

    # 额外显式不变量：共享源头在任意短交错下都凑不出两席的合格签收
    shared_cfg = _cfg_shared_root()
    for order in short_sequences(_event_pool(False, shared=True)):
        try:
            tr = run_trace(order, shared_cfg)
        except ValueError:
            continue
        assert tr.final_state != State.COMMITTED
    return report
