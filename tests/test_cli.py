"""CLI 端到端测试：调用真实命令行入口，校验退出码与结果文档结构。"""
import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class TestCli(unittest.TestCase):
    def test_cli_writes_result_document(self):
        out = ROOT / "tests" / "_tmp_result.json"
        if out.exists():
            out.unlink()
        proc = subprocess.run(
            [sys.executable, "-m", "solution",
             "--input", str(ROOT / "cases.json"), "--output", str(out)],
            cwd=ROOT, capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        doc = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(doc["schema_version"], 1)
        ids = [r["case_id"] for r in doc["results"]]
        self.assertIn("01_mixed_version_exposure", ids)
        # 每个结果都带初始/最终合法性标记
        for r in doc["results"]:
            self.assertIn("initial_state_valid", r)
            self.assertIn("final_state_valid", r)
        out.unlink()

    def test_cli_bad_input_exit_code_2(self):
        bad = ROOT / "tests" / "_tmp_bad.json"
        out = ROOT / "tests" / "_tmp_bad_result.json"
        bad.write_text("{broken", encoding="utf-8")
        proc = subprocess.run(
            [sys.executable, "-m", "solution",
             "--input", str(bad), "--output", str(out)],
            cwd=ROOT, capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 2)
        doc = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(doc["error_code"], "E_JSON")
        bad.unlink(); out.unlink()

    def test_document_contains_diff_and_citations_for_plans(self):
        out = ROOT / "tests" / "_tmp_result.json"
        subprocess.run(
            [sys.executable, "-m", "solution",
             "--input", str(ROOT / "cases.json"), "--output", str(out)],
            cwd=ROOT, check=True, capture_output=True, text=True,
        )
        doc = json.loads(out.read_text(encoding="utf-8"))
        plan = next(r for r in doc["results"] if r["status"] == "plan_found")
        self.assertTrue(plan["steps"])
        # 至少有一个片段带规则出处
        cited = any(
            f["citations"]
            for st in plan["steps"] for pd in st["pair_diffs"]
            for f in pd["added"] + pd["removed"]
        )
        self.assertTrue(cited)
        out.unlink()


if __name__ == "__main__":
    unittest.main()
