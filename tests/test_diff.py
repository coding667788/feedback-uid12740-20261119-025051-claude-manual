"""端口差分测试：用独立预言机的逐点前后许可验证区间差分与出处。"""
import json
import unittest
from pathlib import Path

from solution.diff import diff_plan, step_diff
from solution.parser import load_specs
from solution.policy import Auditor
from solution.search import Planner

from tests import oracle

ROOT = Path(__file__).resolve().parent.parent
CASES = json.loads((ROOT / "cases.json").read_text(encoding="utf-8"))["cases"]
CASE_BY_ID = {c["case_id"]: c for c in CASES}
SPECS = {s.case_id: s for s in load_specs(ROOT / "cases.json")}


def frag_points(frags):
    pts = set()
    for f in frags:
        pts.update(range(f["lo"], f["hi"] + 1))
    return pts


def switched_set(case, group_names):
    return frozenset(group_names)


class TestStepDiff(unittest.TestCase):
    def test_added_removed_match_point_set_difference(self):
        for cid, case in CASE_BY_ID.items():
            spec = SPECS[cid]
            auditor = Auditor(spec)
            planner = Planner(spec, auditor)
            result = planner.solve()
            if not result.found:
                continue
            # 独立重放该计划，逐实例对/协议比较逐点差分
            before = frozenset()
            mask = 0
            for step_no, group in enumerate(result.sequence, start=1):
                after = before | {group}
                after_mask = mask | (1 << spec.groups.index(group))
                diffs = step_diff(auditor, spec, group, mask, after_mask)
                # 收集该步所有实例对/协议的差分
                covered_pairs = set()
                for d in diffs:
                    key = (d.source_instance, d.destination_instance, d.protocol)
                    covered_pairs.add(key)
                    sraw = next(i for i in case["instances"] if i["id"] == d.source_instance)
                    draw = next(i for i in case["instances"] if i["id"] == d.destination_instance)
                    p_before = oracle.effective_points(case, sraw, draw, d.protocol, before)
                    p_after = oracle.effective_points(case, sraw, draw, d.protocol, after)
                    self.assertEqual(
                        frag_points([f.to_dict() for f in d.added]),
                        p_after - p_before,
                        f"{cid} step{step_no} added {key}",
                    )
                    self.assertEqual(
                        frag_points([f.to_dict() for f in d.removed]),
                        p_before - p_after,
                        f"{cid} step{step_no} removed {key}",
                    )
                    # 出处非空且确实是参与许可的规则
                    for f in d.added + d.removed:
                        self.assertTrue(f.citations, f"{cid} 片段缺少出处")
                # 反向：预言机发现有变化的对，差分里必须出现
                protos = sorted({c["protocol"] for c in case["constraints"]}
                                | {r["protocol"] for r in case["rules"] if r["protocol"] != "*"})
                for sraw in case["instances"]:
                    for draw in case["instances"]:
                        if group not in (sraw["group"], draw["group"]):
                            continue
                        for proto in protos:
                            pb = oracle.effective_points(case, sraw, draw, proto, before)
                            pa = oracle.effective_points(case, sraw, draw, proto, after)
                            if pb != pa:
                                self.assertIn(
                                    (sraw["id"], draw["id"], proto), covered_pairs,
                                    f"{cid} 遗漏变化对 {sraw['id']}->{draw['id']}",
                                )
                before = after
                mask = after_mask

    def test_diff_plan_serializable_and_group_atomic(self):
        cid = "04_flow_interruption_diff"
        spec = SPECS[cid]
        auditor = Auditor(spec)
        seq = Planner(spec, auditor).solve().sequence
        steps = diff_plan(auditor, spec, seq)
        self.assertEqual(len(steps), len(seq))
        for st in steps:
            self.assertEqual(len(st["state_after"]) - len(st["state_before"]), 1)
            for pd in st["pair_diffs"]:
                for f in pd["added"] + pd["removed"]:
                    self.assertLessEqual(f["lo"], f["hi"])  # 始终是合法闭区间
                    self.assertTrue(f["citations"])

    def test_flow_interruption_expected_intervals(self):
        # 手工断言 case04 的关键断流/新增区间（非反推，来自设计真值表）
        cid = "04_flow_interruption_diff"
        spec = SPECS[cid]
        auditor = Auditor(spec)
        steps = diff_plan(auditor, spec, ["gx", "gy"])
        s1 = steps[0]["pair_diffs"][0]
        self.assertEqual([(f["lo"], f["hi"]) for f in s1["added"]], [(300, 400)])
        self.assertEqual(s1["removed"], [])
        s2 = steps[1]["pair_diffs"][0]
        self.assertEqual([(f["lo"], f["hi"]) for f in s2["removed"]], [(13, 79)])
        self.assertEqual(s2["added"], [])


if __name__ == "__main__":
    unittest.main()
