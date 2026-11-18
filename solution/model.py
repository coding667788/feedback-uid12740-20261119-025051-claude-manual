"""输入领域对象（不可变 dataclass）。"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from .errors import AuditError, raise_error
from .intervals import Interval

Action = Literal["allow", "deny"]
Side = Literal["outbound", "inbound"]
Kind = Literal["required", "forbidden"]
WILDCARD = "*"  # 协议通配


@dataclass(frozen=True)
class Instance:
    """服务实例：id、所属服务、所属部署组、标签集合。"""

    id: str
    service: str
    group: str
    labels: frozenset[str]


@dataclass(frozen=True)
class Selector:
    """规则端选择器。

    所有给定条件必须同时满足（AND 语义）；省略的维度不限制。
    ``all_`` 为真时匹配该侧任意实例。
    """

    all_: bool = False
    service: str | None = None
    labels: frozenset[str] = frozenset()

    def matches(self, inst: Instance) -> bool:
        if self.all_:
            return True
        if self.service is not None and inst.service != self.service:
            return False
        if self.labels and not self.labels.issubset(inst.labels):
            return False
        return True


@dataclass(frozen=True)
class Rule:
    """一条防火墙规则，属于某个版本（old/new）。"""

    id: str
    version: Literal["old", "new"]
    action: Action
    protocol: str                       # "*" 表示任意协议
    side: Side
    source: Selector
    destination: Selector
    ports: tuple[Interval, ...]         # 归一化后的闭区间

    def matches_endpoints(self, src: Instance, dst: Instance) -> bool:
        return self.source.matches(src) and self.destination.matches(dst)


@dataclass(frozen=True)
class Constraint:
    """全阶段连通性约束。

    required  : [lo,hi] 中每个端口都必须在有效双向许可内；
    forbidden : [lo,hi] 中每个端口都必须不在有效双向许可内。
    """

    id: str
    kind: Kind
    source_service: str
    destination_service: str
    protocol: str
    ports: tuple[Interval, ...]


@dataclass(frozen=True)
class Spec:
    """一次审计的完整输入。"""

    case_id: str
    port_domain: Interval
    services: tuple[str, ...]
    groups: tuple[str, ...]                     # 已按字典序排序
    instances: tuple[Instance, ...]
    rules: tuple[Rule, ...]
    constraints: tuple[Constraint, ...]
    depends_on: dict[str, frozenset[str]]       # 组 -> 必须先切换的前置组
    instances_by_service: dict[str, tuple[Instance, ...]] = field(compare=False)
    instances_by_group: dict[str, tuple[Instance, ...]] = field(compare=False)

    def rule_version_of(self, group: str, switched_mask: int) -> Literal["old", "new"]:
        """组在给定切换状态下实例采用的规则版本。"""
        idx = self.groups.index(group)
        return "new" if (switched_mask >> idx) & 1 else "old"

    def validate_references(self) -> None:
        """构造后引用完整性兜底检查（正常由 parser 提前拦截）。"""
        known_groups = set(self.groups)
        known_services = set(self.services)
        for inst in self.instances:
            if inst.group not in known_groups:
                raise_error("E_DOMAIN", f"实例 {inst.id} 引用未知组 {inst.group}")
            if inst.service not in known_services:
                raise_error("E_DOMAIN", f"实例 {inst.id} 引用未知服务 {inst.service}")
        for g, pre in self.depends_on.items():
            if g not in known_groups:
                raise_error("E_DAG_CYCLE", f"依赖声明引用未知组 {g}")
            unknown = pre - known_groups
            if unknown:
                raise_error("E_DAG_CYCLE", f"组 {g} 的前置依赖引用未知组 {sorted(unknown)}")
        # DAG 环检查。
        color: dict[str, int] = {g: 0 for g in self.groups}

        def visit(node: str, stack: list[str]) -> None:
            color[node] = 1
            for nxt in sorted(self.depends_on.get(node, ())):
                if color[nxt] == 1:
                    cycle = " -> ".join(stack + [nxt])
                    raise_error("E_DAG_CYCLE", f"依赖 DAG 存在环: {cycle}")
                if color[nxt] == 0:
                    visit(nxt, stack + [nxt])
            color[node] = 2

        for g in self.groups:
            if color[g] == 0:
                visit(g, [g])

    @property
    def full_mask(self) -> int:
        return (1 << len(self.groups)) - 1


def assert_domain(lo: int, hi: int, domain: Interval, where: str) -> None:
    """校验闭区间在端口域内且 lo <= hi。"""
    dlo, dhi = domain
    if not (isinstance(lo, int) and isinstance(hi, int)):
        raise_error("E_SCHEMA", f"{where}: 端口必须是整数")
    if lo > hi:
        raise_error("E_SCHEMA", f"{where}: 区间起点 {lo} 大于终点 {hi}")
    if lo < dlo or hi > dhi:
        raise_error("E_DOMAIN", f"{where}: 区间 [{lo},{hi}] 超出端口域 [{dlo},{dhi}]")


__all__ = [
    "Action",
    "AuditError",
    "Constraint",
    "Instance",
    "Rule",
    "Selector",
    "Side",
    "Spec",
    "WILDCARD",
    "assert_domain",
]
