"""cases.json 载入与严格校验。

支持两种顶层形态：
- 单个 case 对象（含 ``case_id``）；
- ``{"schema_version": 1, "cases": [ ... ]}`` 批量形态。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .errors import AuditError, raise_error
from .intervals import Interval, merge
from .model import (
    Constraint,
    Instance,
    Rule,
    Selector,
    Spec,
    assert_domain,
)

SCHEMA_VERSION = 1


def _require(obj: Any, key: str, ctx: str, types: tuple[type, ...]) -> Any:
    if not isinstance(obj, dict) or key not in obj:
        raise_error("E_SCHEMA", f"{ctx}: 缺少必需字段 {key!r}")
    val = obj[key]
    if not isinstance(val, types):
        names = "/".join(t.__name__ for t in types)
        raise_error("E_SCHEMA", f"{ctx}.{key}: 类型应为 {names}，实际为 {type(val).__name__}")
    return val


def _opt(obj: dict, key: str, default: Any, types: tuple[type, ...]) -> Any:
    if key not in obj or obj[key] is None:
        return default
    val = obj[key]
    if not isinstance(val, types):
        names = "/".join(t.__name__ for t in types)
        raise_error("E_SCHEMA", f"{key}: 类型应为 {names}，实际为 {type(val).__name__}")
    return val


def _parse_ports(raw: Any, domain: Interval, ctx: str) -> tuple[Interval, ...]:
    if not isinstance(raw, list) or not raw:
        raise_error("E_SCHEMA", f"{ctx}: ports 必须是非空数组")
    out: list[Interval] = []
    for i, item in enumerate(raw):
        if not isinstance(item, list) or len(item) != 2:
            raise_error("E_SCHEMA", f"{ctx}.ports[{i}]: 必须是 [lo, hi] 二元数组")
        lo, hi = item
        assert_domain(lo, hi, domain, f"{ctx}.ports[{i}]")
        out.append((int(lo), int(hi)))
    merged = merge(out)
    return tuple(merged)


def _parse_selector(raw: Any, ctx: str) -> Selector:
    if raw is None or raw == "*" or raw == "all":
        return Selector(all_=True)
    if not isinstance(raw, dict):
        raise_error("E_SCHEMA", f"{ctx}: 选择器必须是对象、'*' 或 'all'")
    service = _opt(raw, "service", None, (str,))
    labels = _opt(raw, "labels", (), (list,))
    if not all(isinstance(x, str) for x in labels):
        raise_error("E_SCHEMA", f"{ctx}.labels: 必须是字符串数组")
    if not raw:
        return Selector(all_=True)
    return Selector(all_=False, service=service, labels=frozenset(labels))


def _parse_case(raw: dict) -> Spec:
    ctx = f"case[{raw.get('case_id', '?')}]"
    case_id = _require(raw, "case_id", ctx, (str,))
    domain_raw = _opt(raw, "port_domain", [0, 65535], (list,))
    if len(domain_raw) != 2:
        raise_error("E_SCHEMA", f"{ctx}.port_domain: 必须是 [lo, hi]")
    domain_lo, domain_hi = domain_raw
    assert_domain(domain_lo, domain_hi, (0, 65535), f"{ctx}.port_domain")
    domain: Interval = (int(domain_lo), int(domain_hi))

    services = _require(raw, "services", ctx, (list,))
    if not services or not all(isinstance(s, str) for s in services):
        raise_error("E_SCHEMA", f"{ctx}.services: 必须是非空字符串数组")
    if len(set(services)) != len(services):
        raise_error("E_SCHEMA", f"{ctx}.services: 服务 id 重复")

    groups_raw = _require(raw, "groups", ctx, (list,))
    if not groups_raw or not all(isinstance(g, str) for g in groups_raw):
        raise_error("E_SCHEMA", f"{ctx}.groups: 必须是非空字符串数组")
    if len(groups_raw) > 16:
        raise_error("E_SCHEMA", f"{ctx}.groups: 部署组最多 16 个，实际 {len(groups_raw)}")
    if len(set(groups_raw)) != len(groups_raw):
        raise_error("E_SCHEMA", f"{ctx}.groups: 组 id 重复")
    groups = tuple(sorted(groups_raw))

    # 实例。
    inst_raw = _require(raw, "instances", ctx, (list,))
    if not inst_raw:
        raise_error("E_SCHEMA", f"{ctx}.instances: 至少需要一个实例")
    instances: list[Instance] = []
    seen_inst: set[str] = set()
    per_service: dict[str, int] = {}
    for k, item in enumerate(inst_raw):
        ictx = f"{ctx}.instances[{k}]"
        iid = _require(item, "id", ictx, (str,))
        if iid in seen_inst:
            raise_error("E_SCHEMA", f"{ictx}: 实例 id {iid} 重复")
        seen_inst.add(iid)
        svc = _require(item, "service", ictx, (str,))
        if svc not in services:
            raise_error("E_DOMAIN", f"{ictx}: 未知服务 {svc}")
        grp = _require(item, "group", ictx, (str,))
        if grp not in groups_raw:
            raise_error("E_DOMAIN", f"{ictx}: 未知组 {grp}")
        labels = _opt(item, "labels", (), (list,))
        if not all(isinstance(x, str) for x in labels):
            raise_error("E_SCHEMA", f"{ictx}.labels: 必须是字符串数组")
        if len(set(labels)) != len(labels):
            raise_error("E_SCHEMA", f"{ictx}.labels: 标签重复")
        instances.append(Instance(iid, svc, grp, frozenset(labels)))
        per_service[svc] = per_service.get(svc, 0) + 1
    missing = [s for s in services if per_service.get(s, 0) == 0]
    if missing:
        raise_error("E_DOMAIN", f"{ctx}: 服务 {missing} 没有任何实例")

    # 依赖 DAG。
    deps_raw = _opt(raw, "depends_on", {}, (dict,))
    depends_on: dict[str, frozenset[str]] = {}
    for g, pre in deps_raw.items():
        if g not in groups_raw:
            raise_error("E_DAG_CYCLE", f"{ctx}.depends_on: 未知组 {g}")
        if not isinstance(pre, list) or not all(isinstance(x, str) for x in pre):
            raise_error("E_SCHEMA", f"{ctx}.depends_on.{g}: 必须是字符串数组")
        if g in pre:
            raise_error("E_DAG_CYCLE", f"{ctx}.depends_on.{g}: 组不能依赖自身")
        depends_on[g] = frozenset(pre)
    for g in groups:
        depends_on.setdefault(g, frozenset())

    # 规则。
    rules_raw = _require(raw, "rules", ctx, (list,))
    rules: list[Rule] = []
    seen_rules: set[str] = set()
    for k, item in enumerate(rules_raw):
        rctx = f"{ctx}.rules[{k}]"
        rid = _require(item, "id", rctx, (str,))
        if rid in seen_rules:
            raise_error("E_RULE", f"{rctx}: 规则 id {rid} 重复")
        seen_rules.add(rid)
        version = _require(item, "version", rctx, (str,))
        if version not in ("old", "new"):
            raise_error("E_RULE", f"{rctx}.version: 必须是 old 或 new")
        action = _require(item, "action", rctx, (str,))
        if action not in ("allow", "deny"):
            raise_error("E_RULE", f"{rctx}.action: 必须是 allow 或 deny")
        side = _require(item, "side", rctx, (str,))
        if side not in ("outbound", "inbound"):
            raise_error("E_RULE", f"{rctx}.side: 必须是 outbound 或 inbound")
        protocol = _require(item, "protocol", rctx, (str,))
        if not protocol:
            raise_error("E_RULE", f"{rctx}.protocol: 不能为空串")
        src = _parse_selector(_require(item, "source", rctx, (dict, str, type(None))), f"{rctx}.source")
        dst = _parse_selector(_require(item, "destination", rctx, (dict, str, type(None))), f"{rctx}.destination")
        ports = _parse_ports(_require(item, "ports", rctx, (list,)), domain, rctx)
        rules.append(Rule(rid, version, action, protocol, side, src, dst, ports))

    # 约束。
    cons_raw = _opt(raw, "constraints", [], (list,))
    constraints: list[Constraint] = []
    seen_cons: set[str] = set()
    for k, item in enumerate(cons_raw):
        cctx = f"{ctx}.constraints[{k}]"
        cid = _require(item, "id", cctx, (str,))
        if cid in seen_cons:
            raise_error("E_SCHEMA", f"{cctx}: 约束 id {cid} 重复")
        seen_cons.add(cid)
        kind = _require(item, "kind", cctx, (str,))
        if kind not in ("required", "forbidden"):
            raise_error("E_SCHEMA", f"{cctx}.kind: 必须是 required 或 forbidden")
        ssvc = _require(item, "source_service", cctx, (str,))
        dsvc = _require(item, "destination_service", cctx, (str,))
        if ssvc not in services or dsvc not in services:
            raise_error("E_DOMAIN", f"{cctx}: 服务对引用未知服务")
        protocol = _require(item, "protocol", cctx, (str,))
        ports = _parse_ports(_require(item, "ports", cctx, (list,)), domain, cctx)
        constraints.append(Constraint(cid, kind, ssvc, dsvc, protocol, ports))

    spec = Spec(
        case_id=case_id,
        port_domain=domain,
        services=tuple(services),
        groups=groups,
        instances=tuple(instances),
        rules=tuple(rules),
        constraints=tuple(constraints),
        depends_on=depends_on,
        instances_by_service={
            s: tuple(i for i in instances if i.service == s) for s in services
        },
        instances_by_group={
            g: tuple(i for i in instances if i.group == g) for g in groups_raw
        },
    )
    spec.validate_references()
    return spec


def load_specs(path: str | Path) -> list[Spec]:
    """从 JSON 文件载入一个或多个 case。"""
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise AuditError(f"无法读取输入文件 {p}: {exc}", code="E_IO") from exc
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise AuditError(f"JSON 解析失败: {exc}", code="E_JSON") from exc
    if isinstance(data, dict) and "cases" in data:
        sv = data.get("schema_version")
        if sv != SCHEMA_VERSION:
            raise_error("E_JSON", f"schema_version 必须为 {SCHEMA_VERSION}，实际为 {sv!r}")
        raws = data["cases"]
        if not isinstance(raws, list) or not raws:
            raise_error("E_JSON", "cases 必须是非空数组")
        return [_parse_case(r) for r in raws]
    if isinstance(data, dict) and "case_id" in data:
        return [_parse_case(data)]
    raise_error("E_JSON", "顶层必须是 case 对象，或 {'schema_version':1,'cases':[...]}")


def parse_specs_from_text(text: str) -> list[Spec]:
    """供测试使用：直接从 JSON 文本构造。"""
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise AuditError(f"JSON 解析失败: {exc}", code="E_JSON") from exc
    if isinstance(data, dict) and "cases" in data:
        return [_parse_case(r) for r in data["cases"]]
    return [_parse_case(data)]
