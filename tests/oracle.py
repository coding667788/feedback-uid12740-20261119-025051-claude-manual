"""独立判定预言机（不导入 solution 的求值/搜索逻辑）。

仅用 Python 集合与全排列，按最朴素的语义重新实现：
- 逐端口、逐规则、显式拒绝优先地求单端许可；
- 双向许可 = 源出站 ∩ 目的入站；
- 全排列枚举所有满足 DAG 的切换顺序，独立求字典序最小合法序列；
- 独立枚举全部可达合法状态与无解时的最佳状态。

测试用它对照 solution 的区间实现，期望值不来自被测代码。
"""
from __future__ import annotations

import itertools
from typing import Iterable


def _sel_match(sel, inst) -> bool:
    if sel in (None, "*", "all"):
        return True
    if isinstance(sel, str):
        return sel == "all"
    if "service" in sel and sel["service"] != inst["service"]:
        return False
    if sel.get("labels") and not set(sel["labels"]).issubset(set(inst.get("labels", []))):
        return False
    return True


def _proto_match(rule_proto: str, wanted: str) -> bool:
    return rule_proto == "*" or rule_proto == wanted


def _ports_as_points(ports) -> set[int]:
    out: set[int] = set()
    for lo, hi in ports:
        out.update(range(lo, hi + 1))
    return out


def _version_of(case: dict, group: str, switched: frozenset[str]) -> str:
    return "new" if group in switched else "old"


def side_permit_points(case, inst, peer, side, proto, switched) -> set[int]:
    """朴素单端许可：逐端口扫描该版本全部匹配规则，拒绝优先。"""
    version = _version_of(case, inst["group"], switched)
    domain = set(range(case["port_domain"][0], case["port_domain"][1] + 1))
    allowed: set[int] = set()
    denied: set[int] = set()
    for rule in case["rules"]:
        if rule["version"] != version or rule["side"] != side:
            continue
        if not _proto_match(rule["protocol"], proto):
            continue
        if side == "outbound":
            if not (_sel_match(rule["source"], inst) and _sel_match(rule["destination"], peer)):
                continue
        else:
            if not (_sel_match(rule["destination"], inst) and _sel_match(rule["source"], peer)):
                continue
        pts = _ports_as_points(rule["ports"]) & domain
        if rule["action"] == "allow":
            allowed |= pts
        else:
            denied |= pts
    return allowed - denied


def effective_points(case, src, dst, proto, switched) -> set[int]:
    out = side_permit_points(case, src, dst, "outbound", proto, switched)
    inn = side_permit_points(case, dst, src, "inbound", proto, switched)
    return out & inn


def _pairs_for(case, con):
    srcs = [i for i in case["instances"] if i["service"] == con["source_service"]]
    dsts = [i for i in case["instances"] if i["service"] == con["destination_service"]]
    return [(s, d) for s in srcs for d in dsts]


def constraint_violated(case, con, switched) -> bool:
    declared = _ports_as_points(con["ports"])
    for src, dst in _pairs_for(case, con):
        permit = effective_points(case, src, dst, con["protocol"], switched)
        if con["kind"] == "required":
            # 约束内每个已声明端口都必须被许可。
            if not declared.issubset(permit):
                return True
        else:
            if declared & permit:
                return True
    return False


def is_valid(case, switched) -> bool:
    return not any(constraint_violated(case, c, switched) for c in case["constraints"])


def _dag_ok(group, switched, deps) -> bool:
    return all(p in switched for p in deps.get(group, []))


def all_valid_sequences(case) -> list[list[str]]:
    """枚举全部合法完整切换序列（满足 DAG 且每个前缀状态合法）。"""
    groups = list(case["groups"])
    deps = case.get("depends_on", {})
    # 初始空状态也参与校验：初始态违规则不存在任何合法序列
    if not is_valid(case, frozenset()):
        return []
    good: list[list[str]] = []
    for perm in itertools.permutations(groups):
        switched: frozenset[str] = frozenset()
        ok = True
        for g in perm:
            if not _dag_ok(g, switched, deps):
                ok = False
                break
            switched = switched | {g}
            if not is_valid(case, switched):
                ok = False
                break
        if ok and is_valid(case, frozenset(groups)):
            good.append(list(perm))
    return sorted(good)


def lexicographically_smallest(case):
    seqs = all_valid_sequences(case)
    return seqs[0] if seqs else None


def reachable_states(case) -> set[frozenset[str]]:
    """独立 BFS 求全部可达合法状态（frozenset 形式）。"""
    groups = list(case["groups"])
    deps = case.get("depends_on", {})
    start = frozenset()
    if not is_valid(case, start):
        # 初始态违规：没有任何可达的合法状态
        return set()
    seen = {start}
    queue = [start]
    while queue:
        cur = queue.pop(0)
        for g in groups:
            if g in cur or not _dag_ok(g, cur, deps):
                continue
            nxt = cur | {g}
            if nxt not in seen and is_valid(case, nxt):
                seen.add(nxt)
                queue.append(nxt)
    return seen


def best_reachable(case):
    """完成组最多；并列按完成组排序列表字典序。"""
    states = reachable_states(case)
    return min(states, key=lambda s: (-len(s), sorted(s)))


def blocked_next_steps(case, state: frozenset[str]):
    """独立求最佳态每个未切组的阻断原因。"""
    deps = case.get("depends_on", {})
    out = []
    for g in sorted(case["groups"]):
        if g in state:
            continue
        missing = sorted(p for p in deps.get(g, []) if p not in state)
        if missing:
            out.append((g, "dependency", tuple(missing)))
        elif not is_valid(case, state | {g}):
            out.append((g, "constraint", ()))
        else:
            out.append((g, "dead_end", ()))
    return out
