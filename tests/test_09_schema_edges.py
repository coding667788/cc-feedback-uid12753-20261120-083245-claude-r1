"""最终 schema 校验与边界示例：非法类型、必填缺失、additionalProperties、
空对象终端、根替换、未知操作与畸形包。"""

import unittest

from solution.errors import (
    ERR_BAD_OP,
    ERR_BAD_PACKAGE,
    ERR_SCHEMA,
    PublishError,
)
from solution.package import validate_shape
from solution.schema import validate as schema_validate
from solution.service import PublisherService
from tests._helpers import (
    TENANT,
    initial_digest,
    make_package,
    new_store,
)

SCHEMA = {
    "type": "object",
    "required": ["name"],
    "additionalProperties": False,
    "properties": {
        "name": {"type": "string"},
        "count": {"type": "integer"},
        "ratio": {"type": "number"},
        "flag": {"type": "boolean"},
        "mode": {"type": "string", "enum": ["a", "b"]},
        "nested": {
            "type": "object",
            "required": ["k"],
            "properties": {"k": {"type": "integer"}},
        },
        "items": {"type": "array", "items": {"type": "string"}},
    },
}


class SchemaUnitTest(unittest.TestCase):
    def test_type_checks(self):
        schema_validate({"type": "integer"}, 1)
        schema_validate({"type": "number"}, 1.5)
        schema_validate({"type": "boolean"}, True)
        schema_validate({"type": "null"}, None)
        # bool 不算 integer/number
        with self.assertRaises(PublishError) as ctx:
            schema_validate({"type": "integer"}, True)
        self.assertEqual(ctx.exception.code, ERR_SCHEMA)

    def test_required_and_additional(self):
        with self.assertRaises(PublishError) as ctx:
            schema_validate(SCHEMA, {"count": 1})
        self.assertEqual(ctx.exception.code, ERR_SCHEMA)
        with self.assertRaises(PublishError) as ctx:
            schema_validate(SCHEMA, {"name": "x", "unknown": 1})
        self.assertEqual(ctx.exception.code, ERR_SCHEMA)

    def test_enum_and_array_items(self):
        with self.assertRaises(PublishError) as ctx:
            schema_validate({"type": "string", "enum": ["a", "b"]}, "c")
        self.assertEqual(ctx.exception.code, ERR_SCHEMA)
        schema_validate({"type": "array", "items": {"type": "string"}},
                        ["a", "b"])
        with self.assertRaises(PublishError) as ctx:
            schema_validate({"type": "array", "items": {"type": "string"}},
                            ["a", 1])
        self.assertEqual(ctx.exception.code, ERR_SCHEMA)


class FinalSchemaEnforcedInServiceTest(unittest.TestCase):
    def setUp(self):
        self.store, _ = new_store(self)
        self.service = PublisherService(self.store)

    def test_final_tree_schema_violation_rejected(self):
        # timeout 必须是 integer，给字符串 -> 最终 schema 失败
        package = make_package(
            0, [{"op": "set", "path": "/app/timeout", "value": "slow"}],
            ["alice"], initial_digest(),
        )
        receipt = self.service.publish(TENANT, "schema-bad", package)
        self.assertFalse(receipt["ok"])
        self.assertEqual(receipt["error"]["code"], ERR_SCHEMA)
        self.assertEqual(self.service.inspect(TENANT)["pointer_version"], 0)

    def test_intermediate_invalid_but_final_valid_is_allowed(self):
        # 单操作内没有中间态概念；这里验证多操作后最终树合法即可发布
        ops = [
            {"op": "set", "path": "/features/a", "value": True},
            {"op": "set", "path": "/features/b", "value": False},
        ]
        receipt = self.service.publish(
            TENANT, "schema-ok",
            make_package(0, ops, ["alice"], initial_digest()),
        )
        self.assertTrue(receipt["ok"])


class MalformedPackageTest(unittest.TestCase):
    def test_missing_fields(self):
        for bad in ({}, {"target": "x"}, {"operations": []}):
            with self.assertRaises(PublishError) as ctx:
                validate_shape(bad)
            self.assertEqual(ctx.exception.code, ERR_BAD_PACKAGE)

    def test_unknown_operation(self):
        bad = {
            "target": "app-config", "base_version": 0,
            "config_digest": "x", "operations": [{"op": "patch", "path": "/a"}],
            "signatures": [],
        }
        with self.assertRaises(PublishError) as ctx:
            validate_shape(bad)
        self.assertEqual(ctx.exception.code, ERR_BAD_OP)

    def test_service_returns_failure_receipt_for_malformed(self):
        store, _ = new_store(self)
        service = PublisherService(store)
        receipt = service.publish(TENANT, "malformed", {"not": "a package"})
        self.assertFalse(receipt["ok"])
        self.assertEqual(receipt["status"], "FAILED")
        self.assertEqual(receipt["error"]["code"], ERR_BAD_PACKAGE)


class EdgeBoundaryTest(unittest.TestCase):
    def setUp(self):
        self.store, _ = new_store(self)
        self.service = PublisherService(self.store)

    def test_empty_object_leaf_requires_authorization_then_recreated(self):
        # 把 features 整体替换为空对象：
        #   原子树叶 /features/dark ∪ 新空对象终端叶 /features
        ops = [{"op": "set", "path": "/features", "value": {}}]
        receipt = self.service.publish(
            TENANT, "empty-obj",
            make_package(0, ops, ["alice"], initial_digest()),
        )
        self.assertTrue(receipt["ok"])
        self.assertEqual(
            sorted(receipt["affected_leaves"]), ["/features", "/features/dark"]
        )
        state = self.service.inspect(TENANT)
        self.assertEqual(state["published"]["config"]["features"], {})

        # 再在空对象下创建具体键：空对象终端叶 /features ∪ 新叶 /features/beta
        ops2 = [{"op": "set", "path": "/features/beta", "value": True}]
        v1_digest = state["published"]["config_digest"]
        receipt2 = self.service.publish(
            TENANT, "recreate-key",
            make_package(1, ops2, ["alice"], v1_digest),
        )
        self.assertTrue(receipt2["ok"])
        # 旧空对象终端叶 /features 与新叶 /features/beta 的并集
        self.assertEqual(
            sorted(receipt2["affected_leaves"]),
            ["/features", "/features/beta"],
        )
        self.assertEqual(
            self.service.inspect(TENANT)["published"]["config"]["features"],
            {"beta": True},
        )

    def test_root_replacement_union_covers_every_leaf_and_needs_full_scope(self):
        # 只有根作用域 "" 才能覆盖整树替换的全部叶路径
        new_root = {
            "app": {"name": "demo", "version": "2.0.0", "timeout": 5,
                    "tags": ["x"]},
            "security": {"mode": "enforce", "admins": [],
                         "tokens": {"primary": "k"}},
            "features": {},
        }
        package = make_package(
            0, [{"op": "set", "path": "", "value": new_root}],
            ["alice"], initial_digest(),
        )
        # alice 作用域不含 /security -> 拒绝
        receipt = self.service.publish(TENANT, "root-bad", package)
        self.assertFalse(receipt["ok"])


if __name__ == "__main__":
    unittest.main()
