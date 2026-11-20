"""CLI 端到端：python -m solution --input cases.json --output result.json，
并对 cases.json 内每个 expect 做独立断言（期望来自场景文件，非运行结果反推）。
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
CASES = REPO_ROOT / "cases.json"


class CliReplayTest(unittest.TestCase):
    def test_replay_matches_hand_authored_expectations(self):
        with tempfile.TemporaryDirectory(prefix="ocp-cli-") as tmp:
            output = os.path.join(tmp, "result.json")
            db = os.path.join(tmp, "state.sqlite3")
            proc = subprocess.run(
                [sys.executable, "-m", "solution",
                 "--input", str(CASES), "--output", output, "--db", db],
                cwd=str(REPO_ROOT),
                capture_output=True,
                text=True,
                timeout=120,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            with open(output, encoding="utf-8") as fh:
                result = json.load(fh)
            with open(CASES, encoding="utf-8") as fh:
                scenario = json.load(fh)

            self.assertEqual(len(result["results"]), len(scenario["requests"]))
            for actual, request in zip(result["results"], scenario["requests"]):
                expect = request["expect"]
                self.assertEqual(actual["request_id"], request["request_id"])
                self.assertEqual(actual["ok"], expect["ok"], request["request_id"])
                if "error_code" in expect:
                    self.assertEqual(
                        actual["error"]["code"], expect["error_code"],
                        request["request_id"],
                    )
                if "version" in expect:
                    self.assertEqual(
                        actual["version"], expect["version"], request["request_id"]
                    )
                if "replayed" in expect:
                    self.assertEqual(
                        actual["replayed"], expect["replayed"],
                        request["request_id"],
                    )
                if "affected_leaves" in expect:
                    self.assertEqual(
                        actual["affected_leaves"], expect["affected_leaves"],
                        request["request_id"],
                    )

            # 成功版本链与失败不产生快照
            self.assertEqual(result["snapshot_versions"], [0, 1, 2, 3, 4, 5, 6])
            self.assertEqual(result["final_pointer_version"], 6)

            # 数据库文件确实落盘且可被 inspect 重新打开
            self.assertTrue(os.path.exists(db))
            inspect = subprocess.run(
                [sys.executable, "-m", "solution", "inspect",
                 "--db", db, "--tenant", scenario["bootstrap"]["tenant"]],
                cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=60,
            )
            self.assertEqual(inspect.returncode, 0, inspect.stderr)
            state = json.loads(inspect.stdout)
            self.assertEqual(state["pointer_version"], 6)

    def test_replay_is_deterministic_across_runs(self):
        with tempfile.TemporaryDirectory(prefix="ocp-det-") as tmp:
            out1 = os.path.join(tmp, "r1.json")
            out2 = os.path.join(tmp, "r2.json")
            common = ["-m", "solution", "--input", str(CASES)]
            for out in (out1, out2):
                proc = subprocess.run(
                    [sys.executable, *common, "--output", out,
                     "--db", os.path.join(tmp, Path(out).stem + ".sqlite3")],
                    cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=120,
                )
                self.assertEqual(proc.returncode, 0, proc.stderr)
            with open(out1, encoding="utf-8") as fh:
                r1 = json.load(fh)
            with open(out2, encoding="utf-8") as fh:
                r2 = json.load(fh)
            # 去除每次运行不同的绝对 db_path 后应完全一致
            r1.pop("db_path")
            r2.pop("db_path")
            self.assertEqual(r1, r2)


if __name__ == "__main__":
    unittest.main()
