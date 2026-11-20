"""变更包：结构校验、有序 set/delete 应用、受影响叶路径并集。

变更包字段::

    {
      "target": "app-config",                 # 绑定目标
      "base_version": 3,                     # 基准版本
      "config_digest": "<sha256 hex>",       # 基准规范配置摘要
      "operations": [                        # 有序操作
        {"op": "set", "path": "/a/b", "value": 1},
        {"op": "delete", "path": "/x"}
      ],
      "signatures": [                        # 均绑定完整包摘要
        {"identity": "alice", "signature": "<hmac hex>"}
      ]
    }
"""

from __future__ import annotations

from typing import Any

from . import jsonptr
from .errors import ERR_BAD_OP, ERR_BAD_PACKAGE, PublishError

_VALID_OPS = ("set", "delete")


def validate_shape(package: Any) -> None:
    """变更包静态结构校验（不触碰数据库与签名者信息）。"""
    if not isinstance(package, dict):
        raise PublishError(ERR_BAD_PACKAGE, "变更包必须是 JSON 对象")
    for field in ("target", "base_version", "config_digest", "operations", "signatures"):
        if field not in package:
            raise PublishError(ERR_BAD_PACKAGE, f"变更包缺少字段: {field}")
    if not isinstance(package["target"], str) or not package["target"]:
        raise PublishError(ERR_BAD_PACKAGE, "target 必须是非空字符串")
    if isinstance(package["base_version"], bool) or not isinstance(
        package["base_version"], int
    ):
        raise PublishError(ERR_BAD_PACKAGE, "base_version 必须是整数")
    if package["base_version"] < 0:
        raise PublishError(ERR_BAD_PACKAGE, "base_version 不能为负数")
    if not isinstance(package["config_digest"], str) or not package["config_digest"]:
        raise PublishError(ERR_BAD_PACKAGE, "config_digest 必须是非空字符串")
    operations = package["operations"]
    if not isinstance(operations, list) or not operations:
        raise PublishError(ERR_BAD_PACKAGE, "operations 必须是非空数组")
    for index, op in enumerate(operations):
        if not isinstance(op, dict):
            raise PublishError(ERR_BAD_PACKAGE, f"operations[{index}] 必须是对象")
        if op.get("op") not in _VALID_OPS:
            raise PublishError(
                ERR_BAD_OP,
                f"operations[{index}].op 只支持 set/delete，收到 {op.get('op')!r}",
            )
        if not isinstance(op.get("path"), str):
            raise PublishError(ERR_BAD_PACKAGE, f"operations[{index}].path 必须是字符串")
        if op["op"] == "set" and "value" not in op:
            raise PublishError(ERR_BAD_PACKAGE, f"operations[{index}] 缺少 value")
    if not isinstance(package["signatures"], list):
        raise PublishError(ERR_BAD_PACKAGE, "signatures 必须是数组")


def apply_operations(base_config: Any, operations: list[dict]) -> tuple[Any, set[str]]:
    """按数组顺序应用全部操作，返回 (新配置树, 受影响叶路径并集)。

    每一步都基于前一步的结果树计算原/新叶路径，因此并集天然覆盖
    “替换或删除整个对象涉及原树与新树叶路径并集”的要求。
    """
    current = base_config
    affected: set[str] = set()
    for op in operations:
        pointer = op["path"]
        # 操作前后，路径上的终端祖先（空 dict）可能在“叶 ↔ 非叶”间切换，
        # 两个方向都计入受影响叶路径
        old_terminal = jsonptr.terminal_ancestor_paths(current, pointer)
        if op["op"] == "set":
            new_tree, old_subtree = jsonptr.apply_set(current, pointer, op["value"])
            terminal = old_terminal | jsonptr.terminal_ancestor_paths(
                new_tree, pointer
            )
            affected.update(
                jsonptr.affected_leaves(
                    pointer, old_subtree, op["value"], terminal
                )
            )
            current = new_tree
        else:
            new_tree, old_subtree = jsonptr.apply_delete(current, pointer)
            terminal = old_terminal | jsonptr.terminal_ancestor_paths(
                new_tree, pointer
            )
            affected.update(
                jsonptr.affected_leaves(
                    pointer, old_subtree, jsonptr._DELETE_SENTINEL, terminal
                )
            )
            current = new_tree
    return current, affected
