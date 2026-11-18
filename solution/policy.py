"""策略求值引擎。

求值层次：

1. :meth:`Auditor.side_permit` —— 单个实例在某一侧（出站/入站）、某协议下，
   按它**当前所属组的版本**选取规则，显式拒绝优先，得到带规则出处的片段；
2. :meth:`Auditor.effective` —— 源出站 ∩ 目的入站，即该实例对实际双向许可，
   出处同时携带两侧规则 id；
3. :meth:`Auditor.violations` —— 对 required/forbidden 约束逐实例对、逐声明
   闭区间判定（区间包含判定，不逐端口展开）。
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache

from .intervals import (
    Interval,
    Piece,
    contains,
    intersect_tagged,
    sweep_tagged,
    tagged_to_intervals,
)
from .model import Instance, Rule, Spec, WILDCARD


@dataclass(frozen=True)
class Violation:
    """一条约束违规证据。"""

    constraint_id: str
    kind: str
    protocol: str
    source_service: str
    destination_service: str
    source_instance: str
    destination_instance: str
    interval: Interval
    detail: str


def _proto_match(rule_proto: str, wanted: str) -> bool:
    return rule_proto == WILDCARD or rule_proto == wanted


class Auditor:
    """绑定一个 :class:`Spec` 的策略求值器（线程安全，结果带缓存）。"""

    def __init__(self, spec: Spec) -> None:
        self.spec = spec
        # 按版本预切分规则，避免每次求值全表扫描。
        self._rules_by_ver: dict[str, list[Rule]] = {"old": [], "new": []}
        for r in spec.rules:
            self._rules_by_ver[r.version].append(r)

    # ------------------------------------------------------------------ #
    # 单端许可
    # ------------------------------------------------------------------ #
    @lru_cache(maxsize=None)
    def side_permit(
        self,
        inst_id: str,
        side: str,
        protocol: str,
        mask: int,
    ) -> tuple[Piece[str], ...]:
        """实例 inst 在 side 侧、protocol 下的带出处许可片段。

        规则版本由实例所属组在 ``mask`` 下的切换状态决定；
        规则按 (源,目的) 选择器同时匹配两端，再按 side 决定本端语义。
        """
        inst = self._inst_by_id[inst_id]
        version = self.spec.rule_version_of(inst.group, mask)
        sweep_input: list[tuple[Interval, bool, str]] = []
        for rule in self._rules_by_ver[version]:
            if rule.side != side or not _proto_match(rule.protocol, protocol):
                continue
            if side == "outbound":
                if not rule.source.matches(inst):
                    continue
                # 目的选择器仍须可满足：对目的侧无任何限制时总是成立。
                if not self._selector_satisfiable(rule, "destination"):
                    continue
            else:
                if not rule.destination.matches(inst):
                    continue
                if not self._selector_satisfiable(rule, "source"):
                    continue
            for iv in rule.ports:
                sweep_input.append((iv, rule.action == "allow", rule.id))
        return tuple(sweep_tagged(sweep_input))

    @lru_cache(maxsize=None)
    def effective(
        self,
        src_id: str,
        dst_id: str,
        protocol: str,
        mask: int,
    ) -> tuple[Piece[str], ...]:
        """实例对 (src -> dst) 在状态 mask 下的实际双向许可片段。

        只保留同时满足以下三条的规则贡献：源端选择器匹配 src、目的端选择器
        匹配 dst（侧内求值时的可满足性检查不足以保证对端实例匹配），因此
        这里在交集前再按对端选择器过滤一次。
        """
        src = self._inst_by_id[src_id]
        dst = self._inst_by_id[dst_id]
        out_pieces = self._endpoint_permit(src, dst, "outbound", protocol, mask)
        in_pieces = self._endpoint_permit(dst, src, "inbound", protocol, mask)

        def combine(a: frozenset[str], b: frozenset[str]) -> frozenset[str]:
            return a | b

        return tuple(intersect_tagged(out_pieces, in_pieces, combine))

    def effective_intervals(
        self, src_id: str, dst_id: str, protocol: str, mask: int
    ) -> list[Interval]:
        return tagged_to_intervals(self.effective(src_id, dst_id, protocol, mask))

    # ------------------------------------------------------------------ #
    # 约束校验
    # ------------------------------------------------------------------ #
    def violations(self, mask: int) -> list[Violation]:
        """状态 mask 下的全部约束违规（逐实例对、逐声明区间）。"""
        out: list[Violation] = []
        for con in self.spec.constraints:
            srcs = self.spec.instances_by_service[con.source_service]
            dsts = self.spec.instances_by_service[con.destination_service]
            for src in srcs:
                for dst in dsts:
                    permitted = self.effective_intervals(src.id, dst.id, con.protocol, mask)
                    for iv in con.ports:
                        if con.kind == "required":
                            if not contains(permitted, iv[0], iv[1]):
                                out.append(
                                    Violation(
                                        con.id, con.kind, con.protocol,
                                        con.source_service, con.destination_service,
                                        src.id, dst.id, iv,
                                        f"必需连通区间 [{iv[0]},{iv[1]}] 未被完整许可",
                                    )
                                )
                        else:  # forbidden：任一已声明端口被许可即违规
                            if self._overlaps(permitted, iv):
                                out.append(
                                    Violation(
                                        con.id, con.kind, con.protocol,
                                        con.source_service, con.destination_service,
                                        src.id, dst.id, iv,
                                        f"禁止连通区间 [{iv[0]},{iv[1]}] 与实际许可相交",
                                    )
                                )
        return out

    def is_valid(self, mask: int) -> bool:
        return not self.violations(mask)

    # ------------------------------------------------------------------ #
    # 内部
    # ------------------------------------------------------------------ #
    @property
    def _inst_by_id(self) -> dict[str, Instance]:
        if not hasattr(self, "_inst_map"):
            self._inst_map = {i.id: i for i in self.spec.instances}
        return self._inst_map

    def _selector_satisfiable(self, rule: Rule, which: str) -> bool:
        """选择器在全局实例集合上是否可满足（服务/标签是否存在）。"""
        sel = rule.source if which == "source" else rule.destination
        if sel.all_:
            return True
        if sel.service is not None and sel.service not in self.spec.instances_by_service:
            return False
        if sel.labels:
            known = set().union(*(i.labels for i in self.spec.instances)) if self.spec.instances else set()
            if not sel.labels.issubset(known):
                return False
        return True

    def _endpoint_permit(
        self,
        endpoint: Instance,
        peer: Instance,
        side: str,
        protocol: str,
        mask: int,
    ) -> list[Piece[str]]:
        """单端许可，但额外要求对端选择器匹配给定对端实例。"""
        version = self.spec.rule_version_of(endpoint.group, mask)
        sweep_input: list[tuple[Interval, bool, str]] = []
        for rule in self._rules_by_ver[version]:
            if rule.side != side or not _proto_match(rule.protocol, protocol):
                continue
            if side == "outbound":
                if not rule.source.matches(endpoint) or not rule.destination.matches(peer):
                    continue
            else:
                if not rule.destination.matches(endpoint) or not rule.source.matches(peer):
                    continue
            for iv in rule.ports:
                sweep_input.append((iv, rule.action == "allow", rule.id))
        return sweep_tagged(sweep_input)

    @staticmethod
    def _overlaps(intervals: list[Interval], iv: Interval) -> bool:
        lo, hi = iv
        for ilo, ihi in intervals:
            if ihi < lo:
                continue
            if ilo > hi:
                break
            return True
        return False
