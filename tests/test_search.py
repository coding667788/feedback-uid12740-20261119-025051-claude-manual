"""搜索测试：字典序最小序列、可达状态、最佳死路状态与阻断证据，
全部对照独立全排列/BFS 预言机 tests/oracle.py。"""
import json
import unittest
from pathlib import Path

from solution.parser import load_specs
from solution.policy import Auditor
from solution.search import Planner

from tests import oracle

ROOT = Path(__file__).resolve().parent.parent
CASES = json.loads((ROOT / "cases.json").read_text(encoding="utf-8"))["cases"]
CASE_BY_ID = {c["case_id"]: c for c in CASES}
SPECS = {s.case_id: s for s in load_specs(ROOT / "cases.json")}

# 初始态或全量态本身违规的 case 由 CLI 短路（E_INITIAL/E_FINAL），不进入序列搜索
TERMINAL_ERROR_CASES = {"06_final_state_violation", "07_initial_state_violation"}
SEARCHABLE = {k: v for k, v in CASE_BY_ID.items() if k not in TERMINAL_ERROR_CASES}


def mask_to_set(spec, mask):
    return frozenset(g for i, g in enumerate(spec.groups) if (mask >> i) & 1)


class TestSequenceMatchesOracle(unittest.TestCase):
    def test_lexicographically_smallest_or_no_plan(self):
        for cid, case in SEARCHABLE.items():
            spec = SPECS[cid]
            planner = Planner(spec)
            result = planner.solve()
            oracle_seq = oracle.lexicographically_smallest(case)
            if oracle_seq is None:
                self.assertFalse(result.found, cid)
            else:
                self.assertTrue(result.found, cid)
                self.assertEqual(result.sequence, oracle_seq, cid)

    def test_dag_order_respected_in_every_plan(self):
        for cid, case in SEARCHABLE.items():
            spec = SPECS[cid]
            result = Planner(spec).solve()
            if not result.found:
                continue
            deps = case.get("depends_on", {})
            done = set()
            for g in result.sequence:
                for pre in deps.get(g, []):
                    self.assertIn(pre, done, f"{cid}: {g} 在前置 {pre} 之前切换")
                done.add(g)

    def test_every_prefix_state_valid(self):
        for cid, case in SEARCHABLE.items():
            spec = SPECS[cid]
            auditor = Auditor(spec)
            result = Planner(spec, auditor).solve()
            if not result.found:
                continue
            mask = 0
            self.assertTrue(auditor.is_valid(0), cid)
            for g in result.sequence:
                mask |= 1 << spec.groups.index(g)
                self.assertTrue(auditor.is_valid(mask), f"{cid} 切到 {g} 后违规")


class TestReachableAndBest(unittest.TestCase):
    def test_reachable_state_set_matches_oracle(self):
        for cid, case in SEARCHABLE.items():
            spec = SPECS[cid]
            planner = Planner(spec)
            got = {mask_to_set(spec, m) for m in planner.enumerate_reachable()}
            want = oracle.reachable_states(case)
            self.assertEqual(got, want, cid)

    def test_no_plan_best_and_block_evidence(self):
        for cid, case in SEARCHABLE.items():
            spec = SPECS[cid]
            planner = Planner(spec)
            result = planner.solve()
            if result.found:
                continue
            oracle_best = oracle.best_reachable(case)
            self.assertEqual(
                set(result.best_completed), set(oracle_best), cid
            )
            # 完成数确实是可达状态中的最大值
            max_count = max(len(s) for s in oracle.reachable_states(case))
            self.assertEqual(len(result.best_completed), max_count, cid)
            # 阻断原因逐条对照
            oracle_blocks = dict(
                (g, (reason, missing))
                for g, reason, missing in oracle.blocked_next_steps(case, oracle_best)
            )
            self.assertEqual(
                sorted(b.group for b in result.next_step_blocks),
                sorted(oracle_blocks),
                cid,
            )
            for b in result.next_step_blocks:
                reason, missing = oracle_blocks[b.group]
                # popcount 最优准则下，最佳态的合法邻接必更优，故不会出现 dead_end
                self.assertIn(reason, ("dependency", "constraint"))
                self.assertEqual(b.reason, reason, f"{cid}/{b.group}")
                self.assertFalse(b.reachable)
                if reason == "dependency":
                    self.assertEqual(sorted(b.missing_prerequisites), sorted(missing))
                else:
                    self.assertTrue(b.violations, f"{cid}/{b.group} 应有违规证据")


class TestTieAndInitialFinal(unittest.TestCase):
    def test_tie_rejection_both_first_steps_blocked(self):
        case = CASE_BY_ID["02_tie_rejection_no_plan"]
        spec = SPECS[case["case_id"]]
        result = Planner(spec).solve()
        self.assertFalse(result.found)
        self.assertEqual(result.best_completed, [])
        reasons = {b.group: b.reason for b in result.next_step_blocks}
        self.assertEqual(reasons, {"g1": "constraint", "g2": "constraint"})

    def test_initial_invalid_short_circuits(self):
        spec = SPECS["07_initial_state_violation"]
        self.assertFalse(Auditor(spec).is_valid(0))

    def test_final_invalid_detected(self):
        spec = SPECS["06_final_state_violation"]
        auditor = Auditor(spec)
        self.assertTrue(auditor.is_valid(0))
        self.assertFalse(auditor.is_valid(spec.full_mask))


if __name__ == "__main__":
    unittest.main()
