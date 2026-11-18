"""闭整数区间代数。

端口域是有限闭整数区间（默认 [0, 65535]）。所有运算只在区间端点上进行，
绝不逐端口展开，复杂度只与规则条数有关而与端口域宽度无关。

提供两套表示：

1. 普通区间集合 ``list[(lo, hi)]``：归一化后两两互不相交、按起点升序，
   相邻整数区间会被合并（[1,2] 与 [3,4] 合并为 [1,4]，因为闭区间上它们连续）。
2. 带出处片段 ``list[Piece]``：每个片段 ``[lo, hi]`` 携带一个标签集合，
   标签通常是产生该许可的规则 id。显式拒绝优先：某端口只要落在任一拒绝
   规则上，即便同时被允许规则覆盖也不可连通，拒绝规则的挖除不会给被挖掉
   的部分留下任何片段。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Generic, Hashable, Iterable, TypeVar

Interval = tuple[int, int]
T = TypeVar("T", bound=Hashable)


# --------------------------------------------------------------------------- #
# 普通区间集合
# --------------------------------------------------------------------------- #
def merge(intervals: Iterable[Interval]) -> list[Interval]:
    """归一化：排序并合并相交或相邻的闭区间。"""
    pts = sorted((int(lo), int(hi)) for lo, hi in intervals)
    out: list[Interval] = []
    for lo, hi in pts:
        if not out or lo > out[-1][1] + 1:
            out.append((lo, hi))
        elif hi > out[-1][1]:
            out[-1] = (out[-1][0], hi)
    return out


def intersect(a: Iterable[Interval], b: Iterable[Interval]) -> list[Interval]:
    """两个归一化区间集合的交集。"""
    a, b = list(a), list(b)
    i = j = 0
    out: list[Interval] = []
    while i < len(a) and j < len(b):
        lo = max(a[i][0], b[j][0])
        hi = min(a[i][1], b[j][1])
        if lo <= hi:
            out.append((lo, hi))
        if a[i][1] <= b[j][1]:
            i += 1
        else:
            j += 1
    return merge(out)


def subtract(a: Iterable[Interval], b: Iterable[Interval]) -> list[Interval]:
    """``a - b``：从 a 中挖去 b 覆盖的闭区间。"""
    result: list[Interval] = []
    for alo, ahi in a:
        cur_lo = alo
        for blo, bhi in b:
            if bhi < cur_lo:
                continue
            if blo > ahi:
                break
            if blo > cur_lo:
                result.append((cur_lo, min(ahi, blo - 1)))
            cur_lo = max(cur_lo, bhi + 1)
            if cur_lo > ahi:
                break
        if cur_lo <= ahi:
            result.append((cur_lo, ahi))
    return merge(result)


def contains(intervals: Iterable[Interval], lo: int, hi: int) -> bool:
    """闭区间 [lo, hi] 是否被完整包含。"""
    for ilo, ihi in intervals:
        if ilo <= lo and hi <= ihi:
            return True
        if ilo > hi:
            break
    return False


def overlaps(intervals: Iterable[Interval], lo: int, hi: int) -> bool:
    """是否与 [lo, hi] 有公共整数点。"""
    for ilo, ihi in intervals:
        if ihi < lo:
            continue
        if ilo > hi:
            break
        return True
    return False


# --------------------------------------------------------------------------- #
# 带出处的片段
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Piece(Generic[T]):
    """带标签的闭区间片段。"""

    lo: int
    hi: int
    tags: frozenset[T]

    def as_interval(self) -> Interval:
        return (self.lo, self.hi)


def sweep_tagged(rules: Iterable[tuple[Interval, bool, T]]) -> list[Piece[T]]:
    """扫描线构造带出处片段（显式拒绝优先）。

    入参为 ``(区间, 是否允许, 标签)``。扫描线上同时维护活动允许集与活动
    拒绝集：端口可连通当且仅当至少一条允许规则覆盖且没有任何拒绝规则覆盖；
    片段标签集合 = 覆盖该端口的全部允许规则 id。

    事件数为 O(规则数)，输出片段数为 O(规则数)，不随端口域宽度增长。
    """
    # 事件元组：(坐标, 种类[0=进入,1=离开], 是否允许, 标签)。
    events: list[tuple[int, int, bool, T]] = []
    domain_lo: int | None = None
    domain_hi: int | None = None
    for (lo, hi), allow, tag in rules:
        if lo > hi:
            continue
        events.append((lo, 1, allow, tag))       # 进入
        events.append((hi + 1, 0, allow, tag))   # 离开（闭区间，同坐标先于进入处理）
        domain_lo = lo if domain_lo is None else min(domain_lo, lo)
        domain_hi = hi if domain_hi is None else max(domain_hi, hi)
    if not events:
        return []
    assert domain_lo is not None and domain_hi is not None
    events.sort(key=lambda e: (e[0], e[1]))

    active_allow: set[T] = set()
    active_deny: set[T] = set()

    out: list[Piece[T]] = []
    prev = domain_lo
    i = 0
    while i < len(events):
        pos = events[i][0]
        # 发射 [prev, pos-1]：采用本组事件生效前的活动集。
        if pos > prev and active_allow and not active_deny:
            out.append(Piece(prev, pos - 1, frozenset(active_allow)))
        # 成组应用同一坐标的全部事件（进入与离开之间不产生中间段）。
        while i < len(events) and events[i][0] == pos:
            _, _, allow, tag = events[i]
            entering = events[i][1] == 1
            if entering:
                (active_allow if allow else active_deny).add(tag)
            else:
                (active_allow if allow else active_deny).discard(tag)
            i += 1
        prev = pos
    if prev <= domain_hi and active_allow and not active_deny:
        out.append(Piece(prev, domain_hi, frozenset(active_allow)))
    # 融合相邻且标签相同的片段。
    fused: list[Piece[T]] = []
    for p in out:
        if fused and p.lo == fused[-1].hi + 1 and p.tags == fused[-1].tags:
            fused[-1] = Piece(fused[-1].lo, p.hi, p.tags)
        else:
            fused.append(p)
    return fused


def intersect_tagged(
    a: Iterable[Piece[T]],
    b: Iterable[Piece[T]],
    combine: Callable[[frozenset[T], frozenset[T]], frozenset[T]],
) -> list[Piece[T]]:
    """两个带出处片段集合的交集；重叠片段的标签由 ``combine`` 合并。

    双向许可 = 出站许可 ∩ 入站许可，出处因此同时带上两侧规则 id。
    """
    a, b = list(a), list(b)
    i = j = 0
    raw: list[Piece[T]] = []
    while i < len(a) and j < len(b):
        lo = max(a[i].lo, b[j].lo)
        hi = min(a[i].hi, b[j].hi)
        if lo <= hi:
            raw.append(Piece(lo, hi, combine(a[i].tags, b[j].tags)))
        if a[i].hi <= b[j].hi:
            i += 1
        else:
            j += 1
    out: list[Piece[T]] = []
    for p in raw:
        if out and p.lo == out[-1].hi + 1 and p.tags == out[-1].tags:
            out[-1] = Piece(out[-1].lo, p.hi, p.tags)
        else:
            out.append(p)
    return out


def subtract_tagged(a: Iterable[Piece[T]], b: Iterable[Interval]) -> list[Piece[T]]:
    """从带出处片段中挖去普通闭区间（用于额外裁剪），标签保持不变。"""
    out: list[Piece[T]] = []
    b = list(b)
    for piece in a:
        cur_lo = piece.lo
        for blo, bhi in b:
            if bhi < cur_lo:
                continue
            if blo > piece.hi:
                break
            if blo > cur_lo:
                out.append(Piece(cur_lo, min(piece.hi, blo - 1), piece.tags))
            cur_lo = max(cur_lo, bhi + 1)
            if cur_lo > piece.hi:
                break
        if cur_lo <= piece.hi:
            out.append(Piece(cur_lo, piece.hi, piece.tags))
    return out


def tagged_to_intervals(pieces: Iterable[Piece[T]]) -> list[Interval]:
    """丢弃出处，归一化为普通区间集合。"""
    return merge([p.as_interval() for p in pieces])
