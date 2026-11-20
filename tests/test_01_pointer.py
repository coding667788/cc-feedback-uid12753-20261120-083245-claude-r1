"""JSON Pointer 解析、set/delete、叶路径并集与数组禁令的独立断言。

期望值全部在测试内手工构造，不读取 solution 的发布结果。
"""

import unittest

from solution import jsonptr
from solution.errors import (
    ERR_ARRAY_INDEX,
    ERR_INVALID_POINTER,
    ERR_PARENT_NOT_OBJECT,
    ERR_POINTER_NOT_FOUND,
    PublishError,
)


class ParseTest(unittest.TestCase):
    def test_root_and_simple(self):
        self.assertEqual(jsonptr.parse(""), [])
        self.assertEqual(jsonptr.parse("/a/b"), ["a", "b"])

    def test_escape(self):
        self.assertEqual(jsonptr.parse("/a~0b/c~1d"), ["a~b", "c/d"])

    def test_malformed(self):
        for bad in ("a", "/a~2", "/a~"):
            with self.assertRaises(PublishError) as ctx:
                jsonptr.parse(bad)
            self.assertEqual(ctx.exception.code, ERR_INVALID_POINTER)

    def test_roundtrip(self):
        for pointer in ("", "/a", "/a~0b/c~1d", "/security/tokens/primary"):
            self.assertEqual(jsonptr.to_string(jsonptr.parse(pointer)), pointer)


class LeafPathTest(unittest.TestCase):
    def test_scalars_and_nested(self):
        tree = {"a": 1, "b": {"c": 2, "d": {"e": 3}}}
        self.assertEqual(
            set(jsonptr.leaf_paths(tree)),
            {"/a", "/b/c", "/b/d/e"},
        )

    def test_array_is_single_leaf(self):
        tree = {"tags": ["x", "y"], "n": None}
        self.assertEqual(set(jsonptr.leaf_paths(tree)), {"/tags", "/n"})

    def test_empty_container_is_terminal(self):
        # 空对象/空数组自身是叶，保证“删空对象”仍有路径需要授权
        self.assertEqual(set(jsonptr.leaf_paths({})), {""})
        self.assertEqual(set(jsonptr.leaf_paths([])), {""})
        tree = {"obj": {}, "arr": []}
        self.assertEqual(set(jsonptr.leaf_paths(tree)), {"/obj", "/arr"})


class SetDeleteTest(unittest.TestCase):
    def setUp(self):
        self.base = {"a": {"b": 1}, "arr": [1, 2], "x": 1}

    def test_set_existing_leaf(self):
        new_tree, old = jsonptr.apply_set(self.base, "/a/b", 9)
        self.assertEqual(old, 1)
        self.assertEqual(new_tree["a"]["b"], 9)
        self.assertEqual(self.base["a"]["b"], 1)  # 原树不被修改

    def test_set_creates_concrete_key(self):
        new_tree, old = jsonptr.apply_set(self.base, "/a/c", {"d": 2})
        self.assertTrue(jsonptr.is_missing(old))
        self.assertEqual(new_tree["a"]["c"], {"d": 2})

    def test_set_nested_missing_parent_rejected(self):
        with self.assertRaises(PublishError) as ctx:
            jsonptr.apply_set(self.base, "/a/nope/k", 1)
        self.assertEqual(ctx.exception.code, ERR_POINTER_NOT_FOUND)

    def test_set_array_index_forbidden(self):
        with self.assertRaises(PublishError) as ctx:
            jsonptr.apply_set(self.base, "/arr/0", 9)
        self.assertEqual(ctx.exception.code, ERR_ARRAY_INDEX)

    def test_replace_whole_array_as_leaf_allowed(self):
        new_tree, old = jsonptr.apply_set(self.base, "/arr", [9])
        self.assertEqual(old, [1, 2])
        self.assertEqual(new_tree["arr"], [9])

    def test_set_scalar_parent_rejected(self):
        with self.assertRaises(PublishError) as ctx:
            jsonptr.apply_set(self.base, "/x/child", 1)
        self.assertEqual(ctx.exception.code, ERR_PARENT_NOT_OBJECT)

    def test_delete_key(self):
        new_tree, old = jsonptr.apply_delete(self.base, "/x")
        self.assertEqual(old, 1)
        self.assertNotIn("x", new_tree)

    def test_delete_array_index_forbidden(self):
        with self.assertRaises(PublishError) as ctx:
            jsonptr.apply_delete(self.base, "/arr/0")
        self.assertEqual(ctx.exception.code, ERR_ARRAY_INDEX)

    def test_delete_missing_rejected(self):
        with self.assertRaises(PublishError) as ctx:
            jsonptr.apply_delete(self.base, "/nope")
        self.assertEqual(ctx.exception.code, ERR_POINTER_NOT_FOUND)

    def test_delete_root_forbidden(self):
        with self.assertRaises(PublishError) as ctx:
            jsonptr.apply_delete(self.base, "")
        self.assertEqual(ctx.exception.code, ERR_INVALID_POINTER)

    def test_root_replace(self):
        new_tree, old = jsonptr.apply_set(self.base, "", {"z": 0})
        self.assertEqual(old, self.base)
        self.assertEqual(new_tree, {"z": 0})


class AffectedLeavesTest(unittest.TestCase):
    def test_replace_object_is_union_old_and_new(self):
        old = {"primary": "k0"}
        new = {"primary": "k1", "secondary": "k2"}
        leaves = jsonptr.affected_leaves("/security/tokens", old, new)
        self.assertEqual(
            leaves,
            {
                "/security/tokens/primary",
                "/security/tokens/secondary",
            },
        )

    def test_delete_object_only_old_leaves(self):
        old = {"primary": "k0"}
        leaves = jsonptr.affected_leaves(
            "/security/tokens", old, jsonptr._DELETE_SENTINEL
        )
        self.assertEqual(leaves, {"/security/tokens/primary"})

    def test_create_key_only_new_leaves(self):
        new = {"flag": True}
        leaves = jsonptr.affected_leaves(
            "/features/x", jsonptr._MISSING, new
        )
        self.assertEqual(leaves, {"/features/x/flag"})

    def test_array_leaf_counts_whole_path_once(self):
        leaves = jsonptr.affected_leaves("/app/tags", ["a"], ["b", "c"])
        self.assertEqual(leaves, {"/app/tags"})


if __name__ == "__main__":
    unittest.main()
