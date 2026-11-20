"""真实终止自建工作子进程：在“快照写入未提交”与“提交已完成”两处终止，
重启后以数据库状态判断，并核对读者从未见到中间状态。

安全约束：只 terminate/等待本测试用 subprocess 启动的子进程，
绝不按名字杀系统中的其他 Python 进程。
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from solution.barriers import CRASH_EXIT_CODE, release, request_crash, wait_reached
from solution.canonical import config_digest
from solution.service import PublisherService
from solution.store import Store
from tests._helpers import (
    INITIAL_CONFIG,
    SCHEMA,
    SENSITIVE_PREFIXES,
    SIGNERS,
    TENANT,
    TARGET,
    initial_digest,
    load_json,
    make_package,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


class ProcessCrashTest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="ocp-crash-")
        self.db_path = os.path.join(self.tmpdir, "publisher.sqlite3")
        self.barrier_dir = os.path.join(self.tmpdir, "barriers")
        self.receipt_path = os.path.join(self.tmpdir, "receipt.json")
        self.request_path = os.path.join(self.tmpdir, "worker-request.json")

        store = Store(self.db_path)
        store.init_schema()
        store.bootstrap_tenant(
            tenant=TENANT, target=TARGET, schema=SCHEMA,
            sensitive_prefixes=SENSITIVE_PREFIXES,
            initial_config=INITIAL_CONFIG, signers=SIGNERS,
        )

    def _worker_request(self) -> dict:
        package = make_package(
            0, [{"op": "set", "path": "/app/timeout", "value": 45}],
            ["alice"], initial_digest(),
        )
        return {
            "db": self.db_path,
            "barrier_dir": self.barrier_dir,
            "barrier_name": "publish",
            "barrier_timeout": 30.0,
            "tenant": TENANT,
            "request_id": "crash-req",
            "package": package,
            "receipt_path": self.receipt_path,
        }

    def _start_worker(self) -> subprocess.Popen:
        with open(self.request_path, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(self._worker_request(), fh, ensure_ascii=False)
        # cwd 固定仓库根目录，保证 python -m solution 可解析（即便 -I 也能找到）
        return subprocess.Popen(
            [sys.executable, "-m", "solution", "worker",
             "--request", self.request_path],
            cwd=str(REPO_ROOT),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    def _assert_database_clean(self, expected_version: int) -> None:
        """重启视角：重新打开数据库核对最终状态。"""
        store = Store(self.db_path)
        state = PublisherService(store).inspect(TENANT)
        self.assertEqual(state["pointer_version"], expected_version)
        published = state["published"]
        if expected_version == 0:
            self.assertEqual(published["config"], INITIAL_CONFIG)
            self.assertEqual(published["config_digest"], initial_digest())
        else:
            self.assertEqual(published["config"]["app"]["timeout"], 45)
        return state

    def test_kill_before_commit_leaves_no_intermediate_state(self):
        proc = self._start_worker()
        try:
            wait_reached(self.barrier_dir, "publish", "precommit")
            # 子进程已把快照写进未提交事务 -> 请求真实终止
            request_crash(self.barrier_dir, "publish", "precommit")
            proc.wait(timeout=20)
            self.assertEqual(proc.returncode, CRASH_EXIT_CODE)
        finally:
            if proc.poll() is None:
                proc.terminate()
                proc.wait(timeout=10)

        # 无回执文件（进程在写回执前被终止）
        self.assertFalse(os.path.exists(self.receipt_path))

        # 重启后：事务回滚，指针停在 v0，快照链没有 v1
        state = self._assert_database_clean(0)
        self.assertEqual([s["version"] for s in state["snapshots"]], [0])
        # 读者（独立连接）从未见到中间状态
        self.assertEqual(Store(self.db_path).read_published(TENANT)["version"], 0)
        # 幂等表没有该请求（事务整体回滚，未留下任何行）
        self.assertEqual(state["requests"], [])

    def test_kill_after_commit_persists_new_version(self):
        proc = self._start_worker()
        try:
            wait_reached(self.barrier_dir, "publish", "precommit")
            release(self.barrier_dir, "publish", "precommit")
            wait_reached(self.barrier_dir, "publish", "postcommit")
            # 提交已完成 -> 在提交后崩溃点终止
            request_crash(self.barrier_dir, "publish", "postcommit")
            proc.wait(timeout=20)
            self.assertEqual(proc.returncode, CRASH_EXIT_CODE)
        finally:
            if proc.poll() is None:
                proc.terminate()
                proc.wait(timeout=10)

        # 重启后：v1 已持久化，读者只看到已提交版本
        state = self._assert_database_clean(1)
        self.assertEqual([s["version"] for s in state["snapshots"]], [0, 1])
        published = Store(self.db_path).read_published(TENANT)
        self.assertEqual(published["version"], 1)
        self.assertEqual(published["config_digest"],
                         config_digest(state["published"]["config"]))
        # 幂等记录已随事务提交
        self.assertEqual(len(state["requests"]), 1)
        self.assertEqual(state["requests"][0]["status"], "COMMITTED")

    def test_retry_after_precommit_crash_then_succeeds(self):
        # 第一次：提交前终止 -> 回滚
        proc = self._start_worker()
        try:
            wait_reached(self.barrier_dir, "publish", "precommit")
            request_crash(self.barrier_dir, "publish", "precommit")
            proc.wait(timeout=20)
            self.assertEqual(proc.returncode, CRASH_EXIT_CODE)
        finally:
            if proc.poll() is None:
                proc.terminate()
                proc.wait(timeout=10)

        # 清理屏障文件，第二次用新屏障目录正常放行
        import shutil
        shutil.rmtree(self.barrier_dir, ignore_errors=True)
        self.receipt_path = os.path.join(self.tmpdir, "receipt2.json")

        proc2 = self._start_worker()
        try:
            wait_reached(self.barrier_dir, "publish", "precommit")
            release(self.barrier_dir, "publish", "precommit")
            wait_reached(self.barrier_dir, "publish", "postcommit")
            release(self.barrier_dir, "publish", "postcommit")
            proc2.wait(timeout=20)
            self.assertEqual(proc2.returncode, 0)
        finally:
            if proc2.poll() is None:
                proc2.terminate()
                proc2.wait(timeout=10)

        receipt = load_json(self.receipt_path)
        self.assertTrue(receipt["ok"])
        self.assertEqual(receipt["version"], 1)
        self._assert_database_clean(1)


if __name__ == "__main__":
    unittest.main()
