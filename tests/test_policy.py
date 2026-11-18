"""策略求值测试：solution 的区间实现对照独立逐点预言机。

预言机 tests/oracle.py 不导入 solution 的任何求值逻辑，期望值由它独立算出。
"""
import json
import unittest
from pathlib import Path

from solution.parser import load_specs
from solution.policy import Auditor

from tests import oracle

ROOT = Path(__file__).resolve().parent.parent
CASES = json.loads((ROOT / "cases.json").read_text(encoding="utf-8"))["cases"]
CASE_BY_ID = {c["case_id"]: c for c in CASES}
SPECS = {s.case_id: s for s in load_specs(ROOT / "cases.json")}


def all_masks(n):
    return range(1 << n)


class TestEffectiveMatchesOracle(unittest.TestCase):
    def test_every_case_every_mask_every_constraint_pair(self):
        for cid, case in CASE_BY_ID.items():
            spec = SPECS[cid]
            auditor = Auditor(spec)
            n = len(case["groups"])
            group_index = {g: i for i, g in enumerate(spec.groups)}
            for mask in all_masks(n):
                switched = frozenset(
                    g for g in case["groups"] if (mask >> group_index[g]) & 1
                )
                for con in case["constraints"]:
                    proto = con["protocol"]
                    for sraw in case["instances"]:
                        if sraw["service"] != con["source_service"]:
                            continue
                        for draw in case["instances"]:
                            if draw["service"] != con["destination_service"]:
                                continue
                            got = set()
                            for lo, hi in auditor.effective_intervals(
                                sraw["id"], draw["id"], proto, mask
                            ):
                                got.update(range(lo, hi + 1))
                            want = oracle.effective_points(
                                case, sraw, draw, proto, switched
                            )
                            self.assertEqual(
                                got, want,
                                f"{cid} mask={mask} {sraw['id']}->{draw['id']} {proto}",
                            )

    def test_violation_verdicts_match_oracle(self):
        for cid, case in CASE_BY_ID.items():
            spec = SPECS[cid]
            auditor = Auditor(spec)
            n = len(case["groups"])
            group_index = {g: i for i, g in enumerate(spec.groups)}
            for mask in all_masks(n):
                switched = frozenset(
                    g for g in case["groups"] if (mask >> group_index[g]) & 1
                )
                self.assertEqual(
                    auditor.is_valid(mask),
                    oracle.is_valid(case, switched),
                    f"{cid} mask={mask}",
                )


class TestExplicitSemantics(unittest.TestCase):
    def test_deny_precedence_and_protocol_wildcard(self):
        # 手工构造：tcp 允许全域但显式拒绝 25；udp 仅通配规则放行
        case = {
            "port_domain": [1, 5],
            "instances": [
                {"id": "a", "service": "sa", "group": "g", "labels": []},
                {"id": "b", "service": "sb", "group": "g", "labels": []},
            ],
            "rules": [
                {"id": "w", "version": "old", "action": "allow", "protocol": "*",
                 "side": "outbound", "source": "all", "destination": "all",
                 "ports": [[1, 5]]},
                {"id": "d", "version": "old", "action": "deny", "protocol": "tcp",
                 "side": "outbound", "source": "all", "destination": "all",
                 "ports": [[2, 2]]},
            ],
        }
        a, b = case["instances"]
        tcp = oracle.side_permit_points(case, a, b, "outbound", "tcp", frozenset())
        udp = oracle.side_permit_points(case, a, b, "outbound", "udp", frozenset())
        self.assertEqual(tcp, {1, 3, 4, 5})      # 拒绝优先，2 被挖除
        self.assertEqual(udp, {1, 2, 3, 4, 5})   # 通配规则对 udp 生效，无 tcp 拒绝

    def test_multi_port_constraint_every_declared_port(self):
        # required 声明 [1,2] 与 [4,4]，仅许可 1 和 4、缺 2 => 违规
        case = {
            "port_domain": [1, 10],
            "instances": [
                {"id": "a", "service": "sa", "group": "g", "labels": []},
                {"id": "b", "service": "sb", "group": "g", "labels": []},
            ],
            "rules": [
                {"id": "o", "version": "old", "action": "allow", "protocol": "tcp",
                 "side": "outbound", "source": "all", "destination": "all",
                 "ports": [[1, 1], [4, 4]]},
                {"id": "i", "version": "old", "action": "allow", "protocol": "tcp",
                 "side": "inbound", "source": "all", "destination": "all",
                 "ports": [[1, 1], [4, 4]]},
            ],
        }
        con = {"kind": "required", "source_service": "sa",
               "destination_service": "sb", "protocol": "tcp",
               "ports": [[1, 2], [4, 4]]}
        self.assertTrue(oracle.constraint_violated(case, con, frozenset()))
        con2 = dict(con, ports=[[1, 1], [4, 4]])
        self.assertFalse(oracle.constraint_violated(case, con2, frozenset()))

    def test_single_endpoint_self_connection_boundary(self):
        cid = "05_single_endpoint_boundary"
        case = CASE_BY_ID[cid]
        spec = SPECS[cid]
        auditor = Auditor(spec)
        solo = case["instances"][0]
        # 初始态：[1,50] 减去单端口 25
        got = set()
        for lo, hi in auditor.effective_intervals(solo["id"], solo["id"], "tcp", 0):
            got.update(range(lo, hi + 1))
        want = (set(range(1, 51)) - {25})
        self.assertEqual(got, want)
        self.assertEqual(
            got, oracle.effective_points(case, solo, solo, "tcp", frozenset())
        )
        # 目标态：[1,100] 减去闭区间 [24,26]
        got1 = set()
        for lo, hi in auditor.effective_intervals(solo["id"], solo["id"], "tcp", 1):
            got1.update(range(lo, hi + 1))
        self.assertEqual(got1, set(range(1, 101)) - {24, 25, 26})

    def test_side_permit_matches_oracle_side_semantics(self):
        # 单端许可（不做对端交集）也应与预言机的侧内求值一致
        cid = "05_single_endpoint_boundary"
        case = CASE_BY_ID[cid]
        spec = SPECS[cid]
        auditor = Auditor(spec)
        solo = case["instances"][0]
        for mask, switched in ((0, frozenset()), (1, frozenset(["g0"]))):
            for side in ("outbound", "inbound"):
                got = set()
                for piece in auditor.side_permit(solo["id"], side, "tcp", mask):
                    got.update(range(piece.lo, piece.hi + 1))
                want = oracle.side_permit_points(
                    case, solo, solo, side, "tcp", switched
                )
                self.assertEqual(got, want, f"{side} mask={mask}")


if __name__ == "__main__":
    unittest.main()
