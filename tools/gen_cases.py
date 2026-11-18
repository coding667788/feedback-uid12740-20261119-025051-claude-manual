"""合成 cases.json 的可重放生成器（仅标准库）。

运行：python tools/gen_cases.py
所有场景手工设计，期望值在 tests/ 中由独立判定给出。
"""
from __future__ import annotations
import json
from pathlib import Path

CASES: list[dict] = []


def allow(rid, version, side, src, dst, ports, proto="tcp"):
    return {"id": rid, "version": version, "action": "allow",
            "protocol": proto, "side": side, "source": src,
            "destination": dst, "ports": ports}


def deny(rid, version, side, src, dst, ports, proto="tcp"):
    return {"id": rid, "version": version, "action": "deny",
            "protocol": proto, "side": side, "source": src,
            "destination": dst, "ports": ports}


def svc(name):
    return {"service": name}


def con(cid, kind, s, d, ports, proto="tcp"):
    return {"id": cid, "kind": kind, "source_service": s,
            "destination_service": d, "protocol": proto, "ports": ports}


def inst(iid, service, group, labels=None):
    return {"id": iid, "service": service, "group": group,
            "labels": labels or []}

CASES.append({
    "case_id": "01_mixed_version_exposure",
    "comment": "db 先切保持 {10} 干净（合法）；web 先切会瞬时暴露 81（违规），故唯一合法顺序 db,web；目标态新增 200-300 永久许可，全过程区间表示。",
    "port_domain": [1, 1024],
    "services": ["web", "db"],
    "groups": ["db", "web"],
    "instances": [inst("web-1", "web", "web", ["tier=front"]),
                  inst("db-1", "db", "db", ["tier=data"])],
    "depends_on": {},
    "rules": [
        allow("old-web-out", "old", "outbound", svc("web"), svc("db"), [[10, 10]]),
        allow("new-web-out", "new", "outbound", svc("web"), svc("db"),
              [[10, 10], [81, 81], [200, 300]]),
        allow("old-db-in", "old", "inbound", svc("web"), svc("db"),
              [[10, 10], [81, 81]]),
        allow("new-db-in", "new", "inbound", svc("web"), svc("db"),
              [[10, 10], [200, 300]]),
    ],
    "constraints": [
        con("req-10", "required", "web", "db", [[10, 10]]),
        con("forbid-81", "forbidden", "web", "db", [[81, 81]]),
    ],
})

CASES.append({
    "case_id": "02_tie_rejection_no_plan",
    "comment": "两个组任一先切换都立即触发禁止端口（并列拒绝），初始态即死路，最佳状态完成 0 组。",
    "port_domain": [1, 1024],
    "services": ["svc-a", "svc-b"],
    "groups": ["g1", "g2"],
    "instances": [inst("a1", "svc-a", "g1"), inst("b1", "svc-b", "g2")],
    "depends_on": {},
    "rules": [
        allow("old-a-out-x", "old", "outbound", svc("svc-a"), svc("svc-b"),
              [[1, 10], [81, 81]]),
        allow("new-a-out", "new", "outbound", svc("svc-a"), svc("svc-b"),
              [[1, 10], [80, 80]]),
        allow("old-b-in-x", "old", "inbound", svc("svc-a"), svc("svc-b"),
              [[1, 10], [80, 80]]),
        allow("new-b-in", "new", "inbound", svc("svc-a"), svc("svc-b"),
              [[1, 10], [81, 81]]),
    ],
    "constraints": [
        con("forbid-80", "forbidden", "svc-a", "svc-b", [[80, 80]]),
        con("forbid-81", "forbidden", "svc-a", "svc-b", [[81, 81]]),
    ],
})

CASES.append({
    "case_id": "03_local_step_to_dead_end",
    "comment": "g3/g4 可自由切换；带 lock 标签的 a1/b1 构成等价锁，任一先切即违规，最佳状态完成 2 组（g3,g4）且锁无法推进。",
    "port_domain": [1, 1024],
    "services": ["svc-a", "svc-b"],
    "groups": ["g1", "g2", "g3", "g4"],
    "instances": [
        inst("a1", "svc-a", "g1", ["lock"]), inst("a2", "svc-a", "g3"),
        inst("b1", "svc-b", "g2", ["lock"]), inst("b2", "svc-b", "g4"),
    ],
    "depends_on": {},
    "rules": [
        allow("lock-old-out", "old", "outbound",
              {"service": "svc-a", "labels": ["lock"]},
              {"service": "svc-b", "labels": ["lock"]},
              [[1, 10], [81, 81]]),
        allow("lock-new-out", "new", "outbound",
              {"service": "svc-a", "labels": ["lock"]},
              {"service": "svc-b", "labels": ["lock"]},
              [[1, 10], [80, 80]]),
        allow("lock-old-in", "old", "inbound",
              {"service": "svc-a", "labels": ["lock"]},
              {"service": "svc-b", "labels": ["lock"]},
              [[1, 10], [80, 80]]),
        allow("lock-new-in", "new", "inbound",
              {"service": "svc-a", "labels": ["lock"]},
              {"service": "svc-b", "labels": ["lock"]},
              [[1, 10], [81, 81]]),
        allow("free-old-out", "old", "outbound", "all", "all", [[1, 10]]),
        allow("free-new-out", "new", "outbound", "all", "all", [[1, 10]]),
        allow("free-old-in", "old", "inbound", "all", "all", [[1, 10]]),
        allow("free-new-in", "new", "inbound", "all", "all", [[1, 10]]),
    ],
    "constraints": [
        con("forbid-80", "forbidden", "svc-a", "svc-b", [[80, 80]]),
        con("forbid-81", "forbidden", "svc-a", "svc-b", [[81, 81]]),
    ],
})

CASES.append({
    "case_id": "04_flow_interruption_diff",
    "comment": "gx 切换新增 300-400（出站扩区与旧入站相交生效）；gy 切换收回入站 13-79 造成断流；必保 10-12 全程连通，80-81 始终禁止。",
    "port_domain": [1, 1024],
    "services": ["svc-a", "svc-b"],
    "groups": ["gx", "gy"],
    "instances": [inst("a1", "svc-a", "gx"), inst("b1", "svc-b", "gy")],
    "depends_on": {},
    "rules": [
        allow("old-a-out", "old", "outbound", svc("svc-a"), svc("svc-b"), [[1, 79]]),
        allow("old-b-in", "old", "inbound", svc("svc-a"), svc("svc-b"),
              [[1, 79], [300, 400]]),
        allow("new-a-out-allow", "new", "outbound", svc("svc-a"), svc("svc-b"),
              [[1, 79], [300, 400]]),
        deny("new-a-out-deny", "new", "outbound", svc("svc-a"), svc("svc-b"), [[80, 81]]),
        allow("new-b-in", "new", "inbound", svc("svc-a"), svc("svc-b"),
              [[1, 12], [300, 400]]),
    ],
    "constraints": [
        con("req-10-12", "required", "svc-a", "svc-b", [[10, 12]]),
        con("forbid-80-81", "forbidden", "svc-a", "svc-b", [[80, 81]]),
    ],
})

CASES.append({
    "case_id": "05_single_endpoint_boundary",
    "comment": "单实例自连接；闭区间边界 deny 25 与目标 deny [24,26]，验证区间端点与单端口边界。",
    "port_domain": [1, 100],
    "services": ["solo"],
    "groups": ["g0"],
    "instances": [inst("solo-1", "solo", "g0", ["edge"])],
    "depends_on": {},
    "rules": [
        allow("old-out-allow", "old", "outbound", "all", "all", [[1, 50]]),
        deny("old-out-deny", "old", "outbound", "all", "all", [[25, 25]]),
        allow("old-in-allow", "old", "inbound", "all", "all", [[1, 50]]),
        deny("old-in-deny", "old", "inbound", "all", "all", [[25, 25]]),
        allow("new-out-allow", "new", "outbound", "all", "all", [[1, 100]]),
        deny("new-out-deny", "new", "outbound", "all", "all", [[24, 26]]),
        allow("new-in-allow", "new", "inbound", "all", "all", [[1, 100]]),
        deny("new-in-deny", "new", "inbound", "all", "all", [[24, 26]]),
    ],
    "constraints": [
        con("req-self-1-2", "required", "solo", "solo", [[1, 2]]),
        con("forbid-self-25", "forbidden", "solo", "solo", [[25, 25]]),
    ],
})

CASES.append({
    "case_id": "06_final_state_violation",
    "comment": "全量目标态放行禁止端口 80，计划不可能存在，E_FINAL。",
    "port_domain": [1, 1024],
    "services": ["svc-a", "svc-b"],
    "groups": ["g1", "g2"],
    "instances": [inst("a1", "svc-a", "g1"), inst("b1", "svc-b", "g2")],
    "depends_on": {},
    "rules": [
        allow("new-a-out", "new", "outbound", svc("svc-a"), svc("svc-b"), [[1, 100]]),
        allow("new-b-in", "new", "inbound", svc("svc-a"), svc("svc-b"), [[1, 100]]),
    ],
    "constraints": [con("forbid-80", "forbidden", "svc-a", "svc-b", [[80, 80]])],
})

CASES.append({
    "case_id": "07_initial_state_violation",
    "comment": "初始旧规则即放行禁止端口 80，E_INITIAL。",
    "port_domain": [1, 1024],
    "services": ["svc-a", "svc-b"],
    "groups": ["g1"],
    "instances": [inst("a1", "svc-a", "g1"), inst("b1", "svc-b", "g1")],
    "depends_on": {},
    "rules": [
        allow("old-a-out", "old", "outbound", svc("svc-a"), svc("svc-b"), [[80, 80]]),
        allow("old-b-in", "old", "inbound", svc("svc-a"), svc("svc-b"), [[80, 80]]),
        deny("new-a-out", "new", "outbound", svc("svc-a"), svc("svc-b"), [[80, 80]]),
    ],
    "constraints": [con("forbid-80", "forbidden", "svc-a", "svc-b", [[80, 80]])],
})

CASES.append({
    "case_id": "08_dag_prerequisite_order",
    "comment": "ga 依赖 gc；无约束时字典序最小序列为 gb,gc,ga。",
    "port_domain": [1, 1024],
    "services": ["svc-a", "svc-b"],
    "groups": ["ga", "gb", "gc"],
    "instances": [
        inst("a1", "svc-a", "ga"), inst("b1", "svc-b", "gb"),
        inst("c1", "svc-a", "gc"),
    ],
    "depends_on": {"ga": ["gc"]},
    "rules": [
        allow("old-a-out", "old", "outbound", svc("svc-a"), svc("svc-b"), [[1, 100]]),
        allow("old-b-in", "old", "inbound", svc("svc-a"), svc("svc-b"), [[1, 100]]),
        allow("new-a-out", "new", "outbound", svc("svc-a"), svc("svc-b"), [[1, 100]]),
        allow("new-b-in", "new", "inbound", svc("svc-a"), svc("svc-b"), [[1, 100]]),
    ],
    "constraints": [],
})

CASES.append({
    "case_id": "09_dag_dependency_block_evidence",
    "comment": "ga 依赖 gc；gc/gb 等价锁互不可先切；最佳状态完成 0 组，ga 报 dependency、gb/gc 报 constraint。",
    "port_domain": [1, 1024],
    "services": ["svc-a", "svc-b"],
    "groups": ["ga", "gb", "gc"],
    "instances": [
        inst("a1", "svc-a", "ga"), inst("b1", "svc-b", "gb"),
        inst("c1", "svc-a", "gc"),
    ],
    "depends_on": {"ga": ["gc"]},
    "rules": [
        allow("old-a-out-x", "old", "outbound", svc("svc-a"), svc("svc-b"),
              [[1, 10], [81, 81]]),
        allow("new-a-out", "new", "outbound", svc("svc-a"), svc("svc-b"),
              [[1, 10], [80, 80]]),
        allow("old-b-in-x", "old", "inbound", svc("svc-a"), svc("svc-b"),
              [[1, 10], [80, 80]]),
        allow("new-b-in", "new", "inbound", svc("svc-a"), svc("svc-b"),
              [[1, 10], [81, 81]]),
    ],
    "constraints": [
        con("forbid-80", "forbidden", "svc-a", "svc-b", [[80, 80]]),
        con("forbid-81", "forbidden", "svc-a", "svc-b", [[81, 81]]),
    ],
})


CASES.append({
    "case_id": "10_dead_end_reason",
    "comment": "gc 自由可切；锁对 a1/b1 用交叉覆盖，纯旧态与纯新态都干净、仅混合态暴露 80/81。切完 gc 后 ga/gb 单步仍直接违规(constraint)，无 dead_end；另见阻断原因覆盖。",
    "port_domain": [1, 1024],
    "services": ["svc-a", "svc-b"],
    "groups": ["ga", "gb", "gc"],
    "instances": [
        inst("a1", "svc-a", "ga", ["lock"]),
        inst("b1", "svc-b", "gb", ["lock"]),
        inst("c1", "svc-a", "gc"),
    ],
    "depends_on": {},
    "rules": [
        allow("lock-old-out", "old", "outbound",
              {"service": "svc-a", "labels": ["lock"]},
              {"service": "svc-b", "labels": ["lock"]},
              [[1, 10], [81, 81]]),
        allow("lock-new-out", "new", "outbound",
              {"service": "svc-a", "labels": ["lock"]},
              {"service": "svc-b", "labels": ["lock"]},
              [[1, 10], [80, 80]]),
        allow("lock-old-in", "old", "inbound",
              {"service": "svc-a", "labels": ["lock"]},
              {"service": "svc-b", "labels": ["lock"]},
              [[1, 10], [80, 80]]),
        allow("lock-new-in", "new", "inbound",
              {"service": "svc-a", "labels": ["lock"]},
              {"service": "svc-b", "labels": ["lock"]},
              [[1, 10], [81, 81]]),
        allow("free-old-out", "old", "outbound", "all", "all", [[1, 10]]),
        allow("free-new-out", "new", "outbound", "all", "all", [[1, 10]]),
        allow("free-old-in", "old", "inbound", "all", "all", [[1, 10]]),
        allow("free-new-in", "new", "inbound", "all", "all", [[1, 10]]),
    ],
    "constraints": [
        con("forbid-80", "forbidden", "svc-a", "svc-b", [[80, 80]]),
        con("forbid-81", "forbidden", "svc-a", "svc-b", [[81, 81]]),
    ],
})


def main() -> None:
    out = Path(__file__).resolve().parent.parent / "cases.json"
    doc = {"schema_version": 1, "cases": CASES}
    out.write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"wrote {len(CASES)} cases -> {out}")


if __name__ == "__main__":
    main()
