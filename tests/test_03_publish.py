"""端到端发布主路径：版本推进、独立期望配置与摘要、快照不可变。"""

import sqlite3
import unittest

from solution.canonical import config_digest
from solution.service import PublisherService
from tests._helpers import (
    INITIAL_CONFIG,
    TENANT,
    initial_digest,
    make_package,
    new_store,
    ref_apply,
)


class PublishHappyPathTest(unittest.TestCase):
    def setUp(self):
        self.store, self.db_path = new_store(self)
        self.service = PublisherService(self.store)

    def test_bootstrap_version_zero(self):
        state = self.service.inspect(TENANT)
        self.assertEqual(state["pointer_version"], 0)
        self.assertEqual(state["published"]["config"], INITIAL_CONFIG)
        self.assertEqual(state["published"]["config_digest"], initial_digest())

    def test_publish_advances_version_and_matches_independent_expectation(self):
        ops1 = [{"op": "set", "path": "/app/timeout", "value": 45}]
        receipt1 = self.service.publish(
            TENANT, "req-1", make_package(0, ops1, ["alice"], initial_digest())
        )
        self.assertTrue(receipt1["ok"])
        self.assertEqual(receipt1["version"], 1)
        self.assertEqual(receipt1["base_version"], 0)

        expected_v1 = ref_apply(INITIAL_CONFIG, ops1)
        state = self.service.inspect(TENANT)
        self.assertEqual(state["published"]["config"], expected_v1)
        # 摘要由独立参考实现计算，而不是取自回执
        self.assertEqual(
            state["published"]["config_digest"], config_digest(expected_v1)
        )
        self.assertEqual(state["snapshots"][1]["config_digest"],
                         config_digest(expected_v1))

        # 第二次发布基于 v1
        ops2 = [
            {"op": "set", "path": "/security/mode", "value": "enforce"},
        ]
        v1_digest = config_digest(expected_v1)
        receipt2 = self.service.publish(
            TENANT, "req-2",
            make_package(1, ops2, ["carol", "bob"], v1_digest),
        )
        self.assertEqual(receipt2["version"], 2)
        expected_v2 = ref_apply(expected_v1, ops2)
        self.assertEqual(
            self.service.inspect(TENANT)["published"]["config"], expected_v2
        )

    def test_snapshot_chain_is_append_only_and_immutable(self):
        ops = [{"op": "set", "path": "/app/timeout", "value": 45}]
        self.service.publish(
            TENANT, "req-1", make_package(0, ops, ["alice"], initial_digest())
        )
        conn = self.store.connect()
        try:
            versions = [
                row[0]
                for row in conn.execute(
                    "SELECT version FROM config_snapshots ORDER BY version"
                )
            ]
            self.assertEqual(versions, [0, 1])
            with self.assertRaises(sqlite3.IntegrityError):
                conn.execute(
                    "UPDATE config_snapshots SET config_json='{}' WHERE version=0"
                )
            with self.assertRaises(sqlite3.IntegrityError):
                conn.execute("DELETE FROM config_snapshots WHERE version=0")
        finally:
            conn.close()

    def test_restore_old_content_requires_new_authorization_and_version(self):
        # v1：timeout 30 -> 45
        ops_up = [{"op": "set", "path": "/app/timeout", "value": 45}]
        r1 = self.service.publish(
            TENANT, "req-up", make_package(0, ops_up, ["alice"], initial_digest())
        )
        self.assertEqual(r1["version"], 1)

        # 试图复用 v0 的旧签名/旧前置条件（base_version=0）必须被拒
        stale = make_package(0, ops_up, ["alice"], initial_digest())
        rejected = self.service.publish(TENANT, "req-stale", stale)
        self.assertFalse(rejected["ok"])

        # 改回旧值 30：基于当前 v1 重新造包、重新签名，产生新版本 v2
        ops_restore = [{"op": "set", "path": "/app/timeout", "value": 30}]
        v1_digest = self.service.inspect(TENANT)["published"]["config_digest"]
        r2 = self.service.publish(
            TENANT, "req-restore",
            make_package(1, ops_restore, ["alice"], v1_digest),
        )
        self.assertTrue(r2["ok"])
        self.assertEqual(r2["version"], 2)

        state = self.service.inspect(TENANT)
        self.assertEqual(state["pointer_version"], 2)
        # 内容与 v0 相同，但摘要相同、代际不同（v2 是新快照）
        self.assertEqual(state["published"]["config"], INITIAL_CONFIG)
        self.assertEqual(state["published"]["config_digest"], initial_digest())
        self.assertEqual([s["version"] for s in state["snapshots"]], [0, 1, 2])
        # 同摘要的两个不同代快照都在链上
        digests = {s["version"]: s["config_digest"] for s in state["snapshots"]}
        self.assertEqual(digests[0], digests[2])
        self.assertNotEqual(digests[0], digests[1])

    def test_audit_trail_records_each_commit(self):
        ops = [{"op": "set", "path": "/app/timeout", "value": 45}]
        self.service.publish(
            TENANT, "req-1", make_package(0, ops, ["alice"], initial_digest())
        )
        audit = self.service.inspect(TENANT)["audit"]
        events = [row["event"] for row in audit]
        self.assertEqual(events[0], "BOOTSTRAP")
        self.assertIn("PUBLISH", events)
        publish_rows = [row for row in audit if row["event"] == "PUBLISH"]
        self.assertEqual(publish_rows[0]["request_id"], "req-1")

    def test_ordered_operations_match_independent_sequential_expectation(self):
        # 同一包内多个操作按数组顺序生效；期望由独立参考实现逐操作推进
        ops = [
            {"op": "set", "path": "/features/beta", "value": True},
            {"op": "set", "path": "/app/timeout", "value": 7},
            {"op": "set", "path": "/features/beta", "value": False},
        ]
        receipt = self.service.publish(
            TENANT, "ordered",
            make_package(0, ops, ["alice"], initial_digest()),
        )
        self.assertTrue(receipt["ok"])
        expected = INITIAL_CONFIG
        for single in ops:
            expected = ref_apply(expected, [single])
        state = self.service.inspect(TENANT)
        self.assertEqual(state["published"]["config"], expected)
        self.assertEqual(
            state["published"]["config_digest"], config_digest(expected)
        )
        # beta 被写两次，叶路径并集去重后只出现一次
        self.assertEqual(
            sorted(receipt["affected_leaves"]),
            ["/app/timeout", "/features/beta"],
        )

    def test_sensitive_parent_replacement_union_requires_dual_control(self):
        # 整体替换 /security/tokens：原叶与新叶并集都落在高敏区
        ops = [{
            "op": "set", "path": "/security/tokens",
            "value": {"primary": "k-new", "secondary": "k-backup"},
        }]
        # 仅 publisher（carol）-> 双角色拒绝
        denied = self.service.publish(
            TENANT, "sp-denied",
            make_package(0, ops, ["carol"], initial_digest()),
        )
        self.assertFalse(denied["ok"])
        self.assertEqual(
            denied["error"]["code"],
            "HIGH_SENSITIVE_DUAL_CONTROL_REQUIRED",
        )
        # publisher + reviewer -> 通过，且叶路径并集含两个新键
        allowed = self.service.publish(
            TENANT, "sp-ok",
            make_package(0, ops, ["carol", "bob"], initial_digest()),
        )
        self.assertTrue(allowed["ok"])
        self.assertEqual(
            sorted(allowed["affected_leaves"]),
            ["/security/tokens/primary", "/security/tokens/secondary"],
        )
        expected = ref_apply(INITIAL_CONFIG, ops)
        self.assertEqual(
            self.service.inspect(TENANT)["published"]["config"], expected
        )


if __name__ == "__main__":
    unittest.main()
