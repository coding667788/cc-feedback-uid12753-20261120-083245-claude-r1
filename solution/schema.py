"""最终 schema 校验（内置最小子集，仅标准库）。

支持的规则：
  * ``type``: object / array / string / integer / number / boolean / null
  * object: ``properties``、``required``、``additionalProperties``（bool）
  * array:  ``items``（对每个元素生效）
  * 标量:   ``enum``
校验目标是发布事务内重验的**最终配置树**，任何中间态都不作为依据。
"""

from __future__ import annotations

from typing import Any

from .errors import ERR_SCHEMA, PublishError

_TYPE_CHECKS = {
    "object": lambda v: isinstance(v, dict),
    "array": lambda v: isinstance(v, list),
    "string": lambda v: isinstance(v, str),
    "integer": lambda v: isinstance(v, bool) is False and isinstance(v, int),
    "number": lambda v: isinstance(v, bool) is False
    and isinstance(v, (int, float)),
    "boolean": lambda v: isinstance(v, bool),
    "null": lambda v: v is None,
}


def validate(schema: dict, value: Any, path: str = "") -> None:
    """按 schema 校验值，违规抛 :class:`PublishError`。"""
    expected = schema.get("type")
    if expected is not None:
        check = _TYPE_CHECKS.get(expected)
        if check is None:
            raise PublishError(
                ERR_SCHEMA, f"schema 含未知类型 {expected!r}（{path or '/'}）"
            )
        if not check(value):
            raise PublishError(
                ERR_SCHEMA,
                f"{path or '/'} 期望类型 {expected}，实际为 {type(value).__name__}",
            )

    if "enum" in schema and value not in schema["enum"]:
        raise PublishError(
            ERR_SCHEMA, f"{path or '/'} 的值 {value!r} 不在枚举 {schema['enum']!r} 中"
        )

    if expected == "object":
        properties = schema.get("properties", {})
        for required_key in schema.get("required", []):
            if required_key not in value:
                raise PublishError(
                    ERR_SCHEMA,
                    f"{path or '/'} 缺少必填键 {required_key!r}",
                )
        additional = schema.get("additionalProperties", True)
        for key, sub in value.items():
            sub_path = f"{path}/{key}"
            if key in properties:
                validate(properties[key], sub, sub_path)
            elif additional is False:
                raise PublishError(
                    ERR_SCHEMA, f"{sub_path} 是未声明键，additionalProperties=false"
                )
            # additionalProperties=true 且无局部 schema 时接受任意值

    elif expected == "array":
        item_schema = schema.get("items")
        if item_schema is not None:
            for index, sub in enumerate(value):
                validate(item_schema, sub, f"{path}[{index}]")
