"""写事务内重新验证：预检结论不可复用；签名者当前作用域实时生效。"""

import unittest

from solution.errors import (
    ERR_BASE_VERSION,
    ERR_CONFIG_HASH,
    ERR_SIGNER_INACTIVE,
)
from solution.service import PublisherService
from tests._helpers import (
    TENANT,
    initial_digest,
    make_package,
    new_store,
)


class RevalidationTest(unittest.TestCase):
    def setUp(self):
        self.store, _ = new_store(self)
        self.service = PublisherService(self.store)

    def test_precheck_pass_then_revoke_blocks_publish(self):
        package = make_package(
            0, [{"op": "set", "path": "/app/timeout", "value": 45}],
            ["alice"], initial_digest(),
        )
        pre = self.service.precheck(TENANT, "req-pre", package)
        self.assertTrue(pre["ok"])

        # 预检之后、发布之前撤权（停用签名者）
        with self.store.write_transaction() as conn:
            self.store.set_signer_active(conn, TENANT, "alice", False)

        receipt = self.service.publish(TENANT, "req-pre", package)
        self.assertFalse(receipt["ok"])
        self.assertEqual(receipt["error"]["code"], ERR_SIGNER_INACTIVE)
        # 业务状态不变
        self.assertEqual(self.service.inspect(TENANT)["pointer_version"], 0)

    def test_precheck_pass_then_scope_shrunk_blocks_publish(self):
        package = make_package(
            0, [{"op": "set", "path": "/app/timeout", "value": 45}],
            ["alice"], initial_digest(),
        )
        self.assertTrue(self.service.precheck(TENANT, "req-scope", package)["ok"])

        # 作用域收缩到不再覆盖 /app/timeout
        conn = self.store.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "UPDATE signers SET scopes_json=? WHERE tenant=? AND identity=?",
                ('["/app/name"]', TENANT, "alice"),
            )
            conn.commit()
        finally:
            conn.close()

        receipt = self.service.publish(TENANT, "req-scope", package)
        self.assertFalse(receipt["ok"])
        self.assertEqual(receipt["error"]["code"], "SCOPE_DENIED")

    def test_stale_base_version_rejected_in_transaction(self):
        # 先成功一次把指针推到 v1
        first = make_package(
            0, [{"op": "set", "path": "/app/timeout", "value": 45}],
            ["alice"], initial_digest(),
        )
        self.assertTrue(self.service.publish(TENANT, "req-v1", first)["ok"])

        stale = make_package(
            0, [{"op": "set", "path": "/app/timeout", "value": 60}],
            ["alice"], initial_digest(),
        )
        receipt = self.service.publish(TENANT, "req-stale", stale)
        self.assertFalse(receipt["ok"])
        self.assertEqual(receipt["error"]["code"], ERR_BASE_VERSION)

    def test_wrong_config_digest_rejected(self):
        package = make_package(
            0, [{"op": "set", "path": "/app/timeout", "value": 45}],
            ["alice"], initial_digest(),
        )
        # 篡改绑定的基准摘要，并重新签名（签名本身有效，但摘要对不上快照）
        package["config_digest"] = "deadbeef" * 8
        from solution.canonical import package_digest, sign
        from tests._helpers import SECRETS
        digest = package_digest(package)
        package["signatures"] = [
            {"identity": "alice", "signature": sign(digest, SECRETS["alice"])}
        ]
        receipt = self.service.publish(TENANT, "req-badhash", package)
        self.assertFalse(receipt["ok"])
        self.assertEqual(receipt["error"]["code"], ERR_CONFIG_HASH)

    def test_revoked_signer_then_reinstated_publishes(self):
        package = make_package(
            0, [{"op": "set", "path": "/app/timeout", "value": 45}],
            ["alice"], initial_digest(),
        )
        with self.store.write_transaction() as conn:
            self.store.set_signer_active(conn, TENANT, "alice", False)
        blocked = self.service.publish(TENANT, "req-toggle", package)
        self.assertFalse(blocked["ok"])

        with self.store.write_transaction() as conn:
            self.store.set_signer_active(conn, TENANT, "alice", True)
        # 失败请求已占用 req-toggle（失败回执幂等），重新启用后用新 request_id
        allowed = self.service.publish(TENANT, "req-toggle-2", package)
        self.assertTrue(allowed["ok"])
        self.assertEqual(allowed["version"], 1)


if __name__ == "__main__":
    unittest.main()
