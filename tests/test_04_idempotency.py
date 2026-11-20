"""请求 ID 租户内唯一：同 ID 同参返回首次结果，同 ID 异参拒绝；
业务失败回执与业务状态（快照/指针）分离。"""

import unittest

from solution.errors import ERR_REQUEST_PARAM_MISMATCH
from solution.service import PublisherService
from tests._helpers import (
    TENANT,
    initial_digest,
    make_package,
    new_store,
)


class IdempotencyTest(unittest.TestCase):
    def setUp(self):
        self.store, _ = new_store(self)
        self.service = PublisherService(self.store)

    def test_same_id_same_params_returns_first_persisted_result(self):
        package = make_package(
            0, [{"op": "set", "path": "/app/timeout", "value": 45}],
            ["alice"], initial_digest(),
        )
        first = self.service.publish(TENANT, "idem-1", package)
        second = self.service.publish(TENANT, "idem-1", package)
        third = self.service.publish(TENANT, "idem-1", package)

        self.assertTrue(first["ok"])
        self.assertFalse(first["replayed"])
        self.assertTrue(second["ok"])
        self.assertTrue(second["replayed"])
        self.assertTrue(third["replayed"])
        # 始终返回第一次持久化的版本
        self.assertEqual(first["version"], second["version"], third["version"])
        # 只有一个真实快照新版本
        state = self.service.inspect(TENANT)
        self.assertEqual([s["version"] for s in state["snapshots"]], [0, 1])
        # 幂等表只有一行
        self.assertEqual(len(state["requests"]), 1)

    def test_same_id_different_params_rejected(self):
        package_a = make_package(
            0, [{"op": "set", "path": "/app/timeout", "value": 45}],
            ["alice"], initial_digest(),
        )
        first = self.service.publish(TENANT, "idem-2", package_a)
        self.assertTrue(first["ok"])

        package_b = make_package(
            0, [{"op": "set", "path": "/app/timeout", "value": 99}],
            ["alice"], initial_digest(),
        )
        second = self.service.publish(TENANT, "idem-2", package_b)
        self.assertFalse(second["ok"])
        self.assertEqual(second["error"]["code"], ERR_REQUEST_PARAM_MISMATCH)

        # 异参拒绝不改变业务状态，也不抢占 request_id
        state = self.service.inspect(TENANT)
        self.assertEqual(state["pointer_version"], 1)
        self.assertEqual(len(state["requests"]), 1)
        self.assertEqual(state["requests"][0]["status"], "COMMITTED")

    def test_request_id_unique_per_tenant_only(self):
        package = make_package(
            0, [{"op": "set", "path": "/app/timeout", "value": 45}],
            ["alice"], initial_digest(),
        )
        first = self.service.publish(TENANT, "shared-id", package)
        self.assertTrue(first["ok"])
        # 同 ID 再次以相同参数请求 -> 重放（同租户）
        replay = self.service.publish(TENANT, "shared-id", package)
        self.assertTrue(replay["replayed"])

    def test_failed_request_receipt_is_persisted_but_business_state_untouched(self):
        # 高敏单角色：业务必失败
        bad_package = make_package(
            0, [{"op": "set", "path": "/security/mode", "value": "enforce"}],
            ["carol"], initial_digest(),
        )
        receipt = self.service.publish(TENANT, "fail-1", bad_package)
        self.assertFalse(receipt["ok"])
        self.assertEqual(receipt["status"], "FAILED")
        self.assertIsNotNone(receipt["error"])

        state = self.service.inspect(TENANT)
        # 业务状态：指针仍在 v0，没有新快照
        self.assertEqual(state["pointer_version"], 0)
        self.assertEqual([s["version"] for s in state["snapshots"]], [0])
        # 失败回执独立持久化，状态与业务状态可区分
        self.assertEqual(len(state["requests"]), 1)
        row = state["requests"][0]
        self.assertEqual(row["status"], "FAILED")
        self.assertIsNone(row["version"])

        # 同一失败 request_id 同参数重放：返回首次的失败回执（幂等）
        replay = self.service.publish(TENANT, "fail-1", bad_package)
        self.assertFalse(replay["ok"])
        self.assertTrue(replay["replayed"])
        self.assertEqual(receipt["error"]["code"], replay["error"]["code"])

    def test_rejected_request_does_not_consume_request_id(self):
        # 异参拒绝路径（REQUEST_PARAM_MISMATCH）不落幂等行
        package_a = make_package(
            0, [{"op": "set", "path": "/app/timeout", "value": 45}],
            ["alice"], initial_digest(),
        )
        self.service.publish(TENANT, "idem-3", package_a)
        package_b = make_package(
            0, [{"op": "set", "path": "/app/timeout", "value": 77}],
            ["alice"], initial_digest(),
        )
        rejected = self.service.publish(TENANT, "idem-3", package_b)
        self.assertFalse(rejected["ok"])
        state = self.service.inspect(TENANT)
        self.assertEqual(len(state["requests"]), 1)  # 只有 COMMITTED 行


if __name__ == "__main__":
    unittest.main()
