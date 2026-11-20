"""RFC 6901 JSON Pointer 的受限实现与叶路径枚举。

题目约束：
  * ``set`` 允许创建具体键（父节点必须是对象）；
  * 禁止数组下标变化：不能向数组按下标赋值/删除，也不能在数组上创建元素；
  * 数组整体视作叶节点：数组没有可授权的内部路径；
  * 空对象/空数组是终端（自身即为叶路径），保证“删除整个对象”时仍有
    路径需要授权。
"""

from __future__ import annotations

import copy
from typing import Any, Iterator

from .errors import (
    ERR_ARRAY_INDEX,
    ERR_INVALID_POINTER,
    ERR_PARENT_NOT_OBJECT,
    ERR_POINTER_NOT_FOUND,
    PublishError,
)


def parse(pointer: str) -> list[str]:
    """解析 RFC 6901 指针为 token 列表（``""`` 表示根）。"""
    if not isinstance(pointer, str):
        raise PublishError(ERR_INVALID_POINTER, f"指针必须是字符串: {pointer!r}")
    if pointer == "":
        return []
    if not pointer.startswith("/"):
        raise PublishError(
            ERR_INVALID_POINTER, f"非根指针必须以 / 开头: {pointer!r}"
        )
    tokens: list[str] = []
    for raw in pointer.split("/")[1:]:
        if "~" in raw:
            out = []
            i = 0
            while i < len(raw):
                ch = raw[i]
                if ch == "~":
                    if i + 1 >= len(raw) or raw[i + 1] not in "01":
                        raise PublishError(
                            ERR_INVALID_POINTER,
                            f"非法转义序列: {pointer!r}",
                        )
                    out.append("/" if raw[i + 1] == "1" else "~")
                    i += 2
                else:
                    out.append(ch)
                    i += 1
            tokens.append("".join(out))
        else:
            tokens.append(raw)
    return tokens


def to_string(tokens: list[str]) -> str:
    """token 列表转回 RFC 6901 指针。"""
    return "".join(
        "/" + t.replace("~", "~0").replace("/", "~1") for t in tokens
    )


def _is_container(value: Any) -> bool:
    return isinstance(value, (dict, list))


def leaf_paths(value: Any, prefix: list[str] | None = None) -> Iterator[str]:
    """枚举子树中全部叶路径。

    标量与数组整体是叶；dict 继续向下递归；空 dict/空数组自身是终端。
    """
    tokens = prefix or []
    if isinstance(value, dict):
        if not value:
            yield to_string(tokens)
            return
        for key in sorted(value):
            yield from leaf_paths(value[key], tokens + [str(key)])
    else:
        # 标量、None、数组（整体）、空数组
        yield to_string(tokens)


def _navigate_parent(root: Any, tokens: list[str]) -> Any:
    """沿 token 走到最后一个 token 的父节点；数组中途即触发下标禁令。"""
    cur = root
    for token in tokens[:-1]:
        if isinstance(cur, list):
            raise PublishError(
                ERR_ARRAY_INDEX,
                f"禁止数组下标变化，数组整体视作叶: {to_string(tokens)}",
            )
        if not isinstance(cur, dict):
            raise PublishError(
                ERR_PARENT_NOT_OBJECT,
                f"路径父节点不是对象: {to_string(tokens)}",
            )
        if token not in cur:
            raise PublishError(
                ERR_POINTER_NOT_FOUND,
                f"中间路径不存在，无法创建嵌套键: {to_string(tokens)}",
            )
        cur = cur[token]
    return cur


def apply_set(root: Any, pointer: str, value: Any) -> tuple[Any, Any]:
    """有序 set：返回 (新树, 被替换的旧子树)。

    旧子树为 ``_MISSING`` 哨兵表示新建具体键；根替换时旧子树是整棵原树。
    """
    tokens = parse(pointer)
    new_root = copy.deepcopy(root)
    if not tokens:
        return value, root
    parent = _navigate_parent(new_root, tokens)
    if isinstance(parent, list):
        raise PublishError(
            ERR_ARRAY_INDEX,
            f"禁止对数组按下标赋值，数组整体视作叶: {pointer}",
        )
    if not isinstance(parent, dict):
        raise PublishError(
            ERR_PARENT_NOT_OBJECT, f"赋值目标的父节点不是对象: {pointer}"
        )
    key = tokens[-1]
    old = parent.get(key, _MISSING)
    parent[key] = value
    return new_root, old


def apply_delete(root: Any, pointer: str) -> tuple[Any, Any]:
    """有序 delete：返回 (新树, 被删除的旧子树)。根不可删除。"""
    tokens = parse(pointer)
    if not tokens:
        raise PublishError(
            ERR_INVALID_POINTER, "禁止删除根节点（整个配置）"
        )
    new_root = copy.deepcopy(root)
    parent = _navigate_parent(new_root, tokens)
    if isinstance(parent, list):
        raise PublishError(
            ERR_ARRAY_INDEX,
            f"禁止删除数组元素（下标变化），数组整体视作叶: {pointer}",
        )
    if not isinstance(parent, dict):
        raise PublishError(
            ERR_PARENT_NOT_OBJECT, f"删除目标的父节点不是对象: {pointer}"
        )
    key = tokens[-1]
    if key not in parent:
        raise PublishError(ERR_POINTER_NOT_FOUND, f"删除目标不存在: {pointer}")
    old = parent.pop(key)
    return new_root, old


class _Missing:
    """“键原本不存在”的哨兵。"""

    _instance = None

    def __new__(cls) -> "_Missing":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __repr__(self) -> str:  # pragma: no cover - 仅调试用
        return "<MISSING>"


_MISSING = _Missing()


def is_missing(value: Any) -> bool:
    return isinstance(value, _Missing)


def affected_leaves(
    pointer: str,
    old_subtree: Any,
    new_subtree: Any,
    old_terminal_ancestors: set[str] | None = None,
) -> set[str]:
    """计算一项操作最终受影响的叶路径并集。

    * set 新建：仅新子树叶路径；
    * set 替换/delete：原子树叶路径 ∪ 新子树叶路径（delete 无新子树）；
    * ``old_terminal_ancestors``：操作路径上、在**原树**中是终端叶
      （空 dict/空数组）的祖先路径。向空容器内增/删键会让该容器在
      “叶 ↔ 非叶”之间切换，因此它也是受影响叶路径。
    """
    leaves: set[str] = set()
    if not is_missing(old_subtree):
        leaves.update(leaf_paths(old_subtree, parse(pointer)))
    if new_subtree is not _DELETE_SENTINEL:
        leaves.update(leaf_paths(new_subtree, parse(pointer)))
    if old_terminal_ancestors:
        leaves.update(old_terminal_ancestors)
    return leaves


def terminal_ancestor_paths(root: Any, pointer: str) -> set[str]:
    """枚举操作路径上、在给定树中当前为终端叶（空 dict）的祖先路径。

    向空容器内增/删键会让该容器在“叶 ↔ 非叶”之间切换，因此它也是
    受影响叶路径。根为 ``""``；标量/数组祖先不会出现（结构校验已禁止
    穿透它们）。
    """
    tokens = parse(pointer)
    result: set[str] = set()
    cur = root
    for depth in range(len(tokens) - 1):
        # cur 位于路径 tokens[:depth] 上（depth=0 时为根）
        if isinstance(cur, dict) and not cur:
            result.add(to_string(tokens[:depth]))
        if not isinstance(cur, dict) or tokens[depth] not in cur:
            # 中间路径断裂（如向不存在的嵌套键赋值）：后续无祖先可枚举，
            # 结构错误仍由 apply_set/apply_delete 负责拒绝
            return result
        cur = cur[tokens[depth]]
    # 循环结束后 cur 是直接父节点（tokens[:-1]），也要检查一次
    if isinstance(cur, dict) and not cur:
        result.add(to_string(tokens[:-1]))
    return result


class _DeleteSentinel:
    """delete 操作没有“新子树”的哨兵。"""


_DELETE_SENTINEL = _DeleteSentinel()
