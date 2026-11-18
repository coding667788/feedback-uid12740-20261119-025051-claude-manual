"""每步双向许可的端口片段差分。

切换组 g 只可能改变端点位于 g 内的实例对（其它实例采用的规则版本不变）。
对每个受影响的有序实例对、每个相关协议，比较切换前后的实际双向许可：

- added  : 切换后新许可的闭区间片段；
- removed: 切换后被收回的闭区间片段；
并为每个片段给出规则出处（出站侧规则 id ∪ 入站侧规则 id）。

全程区间运算，不逐端口展开。
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .intervals import (
    Interval,
    Piece,
    intersect,
    subtract,
    tagged_to_intervals,
)
from .model import Spec, WILDCARD
from .policy import Auditor


@dataclass
class Fragment:
    lo: int
    hi: int
    citations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"lo": self.lo, "hi": self.hi, "citations": self.citations}


@dataclass
class PairDiff:
    source_instance: str
    destination_instance: str
    protocol: str
    added: list[Fragment]
    removed: list[Fragment]


def _collect_protocols(spec: Spec) -> list[str]:
    """收集约束与规则中出现过的显式协议（通配本身不单独求值）。"""
    protos = {c.protocol for c in spec.constraints if c.protocol != WILDCARD}
    protos.update(r.protocol for r in spec.rules if r.protocol != WILDCARD)
    return sorted(protos)


def _fragments_from_pieces(
    pieces: list[Piece[str]],
    within: list[Interval] | None = None,
) -> list[Fragment]:
    """把带出处片段转为输出 Fragment；可选地只保留 within 内的部分。"""
    if within is not None:
        keep = intersect(tagged_to_intervals(pieces), within)
    else:
        keep = tagged_to_intervals(pieces)
    out: list[Fragment] = []
    for lo, hi in keep:
        cites: set[str] = set()
        for p in pieces:
            if p.hi < lo:
                continue
            if p.lo > hi:
                break
            if p.lo <= hi and p.hi >= lo:
                cites.update(p.tags)
        out.append(Fragment(lo, hi, sorted(cites)))
    return out


def step_diff(
    auditor: Auditor,
    spec: Spec,
    group: str,
    before_mask: int,
    after_mask: int,
) -> list[PairDiff]:
    """计算切换 ``group``（before_mask -> after_mask）的全部非空差分。"""
    touched = set(spec.instances_by_group[group])
    protocols = _collect_protocols(spec)
    results: list[PairDiff] = []

    ordered = list(spec.instances)
    for src in ordered:
        for dst in ordered:
            if src not in touched and dst not in touched:
                continue
            for proto in protocols:
                before = auditor.effective(src.id, dst.id, proto, before_mask)
                after = auditor.effective(src.id, dst.id, proto, after_mask)
                before_iv = tagged_to_intervals(before)
                after_iv = tagged_to_intervals(after)
                added_iv = subtract(after_iv, before_iv)
                removed_iv = subtract(before_iv, after_iv)
                if not added_iv and not removed_iv:
                    continue
                added = _fragments_from_pieces(list(after), within=added_iv)
                removed = _fragments_from_pieces(list(before), within=removed_iv)
                results.append(
                    PairDiff(
                        source_instance=src.id,
                        destination_instance=dst.id,
                        protocol=proto,
                        added=added,
                        removed=removed,
                    )
                )
    return results


def diff_plan(
    auditor: Auditor,
    spec: Spec,
    sequence: list[str],
) -> list[dict]:
    """对完整计划逐步生成可 JSON 序列化的差分记录。"""
    mask = 0
    steps: list[dict] = []
    for step_no, group in enumerate(sequence, start=1):
        before = mask
        after = mask | (1 << spec.groups.index(group))
        pair_diffs = step_diff(auditor, spec, group, before, after)
        steps.append(
            {
                "step": step_no,
                "switch_group": group,
                "state_before": _state_names(spec, before),
                "state_after": _state_names(spec, after),
                "pair_diffs": [
                    {
                        "source_instance": d.source_instance,
                        "destination_instance": d.destination_instance,
                        "protocol": d.protocol,
                        "added": [f.to_dict() for f in d.added],
                        "removed": [f.to_dict() for f in d.removed],
                    }
                    for d in pair_diffs
                ],
            }
        )
        mask = after
    return steps


def _state_names(spec: Spec, mask: int) -> list[str]:
    return [g for i, g in enumerate(spec.groups) if (mask >> i) & 1]
