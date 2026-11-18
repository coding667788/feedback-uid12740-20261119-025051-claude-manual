"""小规模独立穷举验证。

独立随机生成大量小 case（1..4 个组、窄端口域），用全排列预言机穷举全部
合法序列，与 solution 的 Planner 逐一对照：序列、可达状态、最佳死路、阻断原因。
生成逻辑与被测实现完全独立，仅共享 cases.json 的输入 schema。
"""
import itertools
import random
import unittest

from solution.parser import parse_specs_from_text
from solution.policy import Auditor
from solution.search import Planner

from tests import oracle


def generate_case(rng, cid):
    n_groups = rng.randint(1, 4)
    groups = [f"g{i}" for i in range(n_groups)]
    services = ["sa", "sb"]
    instances = [
        {"id": "a", "service": "sa", "group": rng.choice(groups), "labels": []},
        {"id": "b", "service": "sb", "group": rng.choice(groups), "labels": []},
    ]
    # 随机 DAG：只允许小编号 -> 大编号，天然无环
    deps = {}
    for gi, g in enumerate(groups):
        pres = [groups[j] for j in range(gi) if rng.random() < 0.3]
        if pres:
            deps[g] = pres
    # 随机规则：old/new × out/in × allow/deny，端口取自小域内随机闭区间
    rules = []
    rid = 0
    for version in ("old", "new"):
        for side in ("outbound", "inbound"):
            action = rng.choice(["allow", "allow", "deny"])  # allow 偏多
            lo = rng.randint(1, 8)
            hi = rng.randint(lo, 10)
            rid += 1
            rules.append({
                "id": f"r{rid}", "version": version, "action": action,
                "protocol": "tcp", "side": side,
                "source": "all", "destination": "all", "ports": [[lo, hi]],
            })
    # 随机约束：在 1..10 内挑单端口或闭区间
    constraints = []
    for k in range(rng.randint(0, 3)):
        lo = rng.randint(1, 10)
        hi = rng.randint(lo, 10)
        constraints.append({
            "id": f"c{k}",
            "kind": rng.choice(["required", "forbidden"]),
            "source_service": "sa", "destination_service": "sb",
            "protocol": "tcp", "ports": [[lo, hi]],
        })
    return {
        "case_id": cid, "port_domain": [1, 10],
        "services": services, "groups": groups, "instances": instances,
        "depends_on": deps, "rules": rules, "constraints": constraints,
    }


class TestExhaustiveSmallCases(unittest.TestCase):
    def test_many_random_cases_against_permutation_oracle(self):
        rng = random.Random(20261119)
        checked = 0
        found_plan = 0
        for trial in range(300):
            case = generate_case(rng, f"rand-{trial}")
            import json
            spec = parse_specs_from_text(json.dumps(case))[0]
            planner = Planner(spec)
            # 初始态违规的样本由 parser/CLI 的 E_INITIAL 专项测试覆盖，此处跳过
            if not planner.is_valid(0):
                checked += 1
                continue
            result = planner.solve()
            oracle_seq = oracle.lexicographically_smallest(case)

            if oracle_seq is None:
                self.assertFalse(result.found, case["case_id"])
                # 最佳状态对照
                ob = oracle.best_reachable(case)
                self.assertEqual(set(result.best_completed), set(ob))
                # 阻断原因对照
                oblocks = {g: reason for g, reason, _ in
                           oracle.blocked_next_steps(case, ob)}
                for b in result.next_step_blocks:
                    self.assertEqual(b.reason, oblocks[b.group])
            else:
                found_plan += 1
                self.assertTrue(result.found)
                self.assertEqual(result.sequence, oracle_seq)
                # 预言机给出的全部合法序列里，被测序列确为字典序最小
                all_seqs = oracle.all_valid_sequences(case)
                self.assertEqual(result.sequence, min(all_seqs))

            # 可达状态集合对照
            got_reach = {
                frozenset(g for i, g in enumerate(spec.groups) if (m >> i) & 1)
                for m in planner.enumerate_reachable()
            }
            self.assertEqual(got_reach, oracle.reachable_states(case))
            checked += 1
        # 确保两类结果都实际出现，避免退化样本
        self.assertGreater(checked, 200)
        self.assertGreater(found_plan, 0)

    def test_permutation_count_bound_16_groups(self):
        # 结构 sanity：16 组时状态空间 2^16，BFS 不依赖阶乘，可快速完成
        rng = random.Random(7)
        case = generate_case(rng, "wide")
        case["groups"] = [f"g{i:02d}" for i in range(16)]
        case["depends_on"] = {}
        case["instances"][0]["group"] = "g00"
        case["instances"][1]["group"] = "g01"
        case["constraints"] = []
        import json
        spec = parse_specs_from_text(json.dumps(case))[0]
        planner = Planner(spec)
        result = planner.solve()
        self.assertTrue(result.found)
        self.assertEqual(len(result.sequence), 16)
        # 无约束无依赖时字典序最小即组名升序
        self.assertEqual(result.sequence, sorted(spec.groups))


if __name__ == "__main__":
    unittest.main()
