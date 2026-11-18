"""解析与错误码测试：覆盖 schema/域/DAG/重复 id 等输入错误。"""
import unittest

from solution.errors import AuditError
from solution.parser import parse_specs_from_text

BASE = {
    "case_id": "x", "port_domain": [1, 100],
    "services": ["sa", "sb"], "groups": ["g1"],
    "instances": [
        {"id": "a", "service": "sa", "group": "g1"},
        {"id": "b", "service": "sb", "group": "g1"},
    ],
    "rules": [
        {"id": "r1", "version": "old", "action": "allow", "protocol": "tcp",
         "side": "outbound", "source": "all", "destination": "all",
         "ports": [[1, 10]]},
    ],
    "constraints": [],
}
import copy


class TestParserErrors(unittest.TestCase):
    def _expect(self, mutate, code):
        raw = copy.deepcopy(BASE)
        mutate(raw)
        import json
        with self.assertRaises(AuditError) as ctx:
            parse_specs_from_text(json.dumps(raw))
        self.assertEqual(ctx.exception.code, code)

    def test_bad_json(self):
        with self.assertRaises(AuditError) as ctx:
            parse_specs_from_text("{not json")
        self.assertEqual(ctx.exception.code, "E_JSON")

    def test_missing_field(self):
        self._expect(lambda r: r.pop("services"), "E_SCHEMA")

    def test_port_out_of_domain(self):
        self._expect(lambda r: r["rules"][0]["ports"].append([101, 200]), "E_DOMAIN")

    def test_inverted_interval(self):
        self._expect(lambda r: r["rules"][0].__setitem__("ports", [[9, 5]]), "E_SCHEMA")

    def test_unknown_group_reference(self):
        self._expect(lambda r: r["instances"][0].__setitem__("group", "nope"), "E_DOMAIN")

    def test_duplicate_rule_id(self):
        def m(r):
            r["rules"].append(dict(r["rules"][0]))
        self._expect(m, "E_RULE")

    def test_too_many_groups(self):
        def m(r):
            r["groups"] = [f"g{i}" for i in range(17)]
            r["instances"][0]["group"] = "g0"
            r["instances"][1]["group"] = "g0"
        self._expect(m, "E_SCHEMA")

    def test_dag_self_dependency(self):
        self._expect(lambda r: r.__setitem__("depends_on", {"g1": ["g1"]}), "E_DAG_CYCLE")

    def test_dag_cycle(self):
        def m(r):
            r["groups"] = ["g1", "g2"]
            r["instances"][1]["group"] = "g2"
            r["depends_on"] = {"g1": ["g2"], "g2": ["g1"]}
        self._expect(m, "E_DAG_CYCLE")

    def test_service_without_instance(self):
        self._expect(lambda r: r["services"].append("orphan"), "E_DOMAIN")

    def test_bad_action(self):
        self._expect(lambda r: r["rules"][0].__setitem__("action", "maybe"), "E_RULE")


class TestParserHappyPath(unittest.TestCase):
    def test_loads_and_normalizes_ports(self):
        import json
        raw = copy.deepcopy(BASE)
        raw["rules"][0]["ports"] = [[1, 4], [5, 8]]  # 相邻应归一化合并
        specs = parse_specs_from_text(json.dumps(raw))
        self.assertEqual(specs[0].rules[0].ports, ((1, 8),))

    def test_batch_document(self):
        import json
        doc = {"schema_version": 1, "cases": [BASE, BASE]}
        specs = parse_specs_from_text(json.dumps(doc))
        self.assertEqual(len(specs), 2)


if __name__ == "__main__":
    unittest.main()
