"""生成可重放的 cases.json（离线合成输入，不依赖被测实现反推期望）。

独立性说明：
  * 本脚本只复用“规范化哈希 + HMAC”两个密码学原语来制作签名与摘要，
    它们是测试夹具本身的一部分；
  * 基准配置摘要由本脚本内**独立的参考演进函数** ``ref_apply`` 逐版本
    计算（普通字典操作，不导入 solution 的指针/发布实现）；
  * 每个请求的期望错误码、期望版本号均手工明确写在 expect 中，
    测试侧再以独立断言复核，绝不从 solution 的运行结果反推。
"""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from solution.canonical import config_digest, package_digest, sign  # noqa: E402

TENANT = "t1"
TARGET = "app-config"

SCHEMA = {
    "type": "object",
    "required": ["app", "security"],
    "additionalProperties": True,
    "properties": {
        "app": {
            "type": "object",
            "required": ["name", "version"],
            "additionalProperties": True,
            "properties": {
                "name": {"type": "string"},
                "version": {"type": "string"},
                "timeout": {"type": "integer"},
                "tags": {"type": "array", "items": {"type": "string"}},
            },
        },
        "security": {
            "type": "object",
            "required": ["mode"],
            "additionalProperties": True,
            "properties": {
                "mode": {"type": "string", "enum": ["off", "audit", "enforce"]},
                "admins": {"type": "array", "items": {"type": "string"}},
                "tokens": {
                    "type": "object",
                    "required": ["primary"],
                    "additionalProperties": False,
                    "properties": {
                        "primary": {"type": "string"},
                        "secondary": {"type": "string"},
                    },
                },
            },
        },
        "features": {
            "type": "object",
            "additionalProperties": {"type": "boolean"},
        },
    },
}

INITIAL_CONFIG = {
    "app": {
        "name": "demo",
        "version": "1.0.0",
        "timeout": 30,
        "tags": ["stable"],
    },
    "security": {
        "mode": "audit",
        "admins": ["root"],
        "tokens": {"primary": "k-initial"},
    },
    "features": {"dark": False},
}

SENSITIVE_PREFIXES = ["/security"]

SIGNERS = [
    {
        "identity": "alice",
        "role": "publisher",
        "scopes": ["/app", "/features"],
        "secret": "secret-alice",
        "active": True,
    },
    {
        "identity": "bob",
        "role": "reviewer",
        "scopes": ["/security", "/app"],
        "secret": "secret-bob",
        "active": True,
    },
    {
        "identity": "carol",
        "role": "publisher",
        "scopes": ["/security"],
        "secret": "secret-carol",
        "active": True,
    },
    {
        "identity": "dave",
        "role": "publisher",
        "scopes": ["/app/name"],
        "secret": "secret-dave",
        "active": True,
    },
]
SECRETS = {item["identity"]: item["secret"] for item in SIGNERS}


# ------------------------------------------------- 独立参考实现（不经过被测代码）
def ref_apply(config: dict, operations: list[dict]) -> dict:
    """生成器自用的最小参考变更器：仅支持本场景用到的对象内 set/delete。"""
    result = copy.deepcopy(config)
    for op in operations:
        tokens = op["path"].split("/")[1:]
        parent = result
        for token in tokens[:-1]:
            parent = parent[token]
        if op["op"] == "set":
            parent[tokens[-1]] = copy.deepcopy(op["value"])
        else:
            del parent[tokens[-1]]
    return result


def make_package(
    base_version: int,
    operations: list[dict],
    signer_ids: list[str],
    base_config_digest: str,
    tamper_signature: bool = False,
    target: str = TARGET,
) -> dict:
    package = {
        "target": target,
        "base_version": base_version,
        "config_digest": base_config_digest,
        "operations": operations,
        "signatures": [],
    }
    digest = package_digest(package)
    for identity in signer_ids:
        signature = sign(digest, SECRETS[identity])
        if tamper_signature:
            signature = "0" * len(signature)
        package["signatures"].append({"identity": identity, "signature": signature})
    return package


def main() -> None:
    v0_digest = config_digest(INITIAL_CONFIG)

    # 参考演进表：version -> 该版本配置的规范摘要（独立计算）
    digest_at: dict[int, str] = {0: v0_digest}
    ref_config = copy.deepcopy(INITIAL_CONFIG)
    next_ref_version = 1

    def record_success(operations: list[dict]) -> None:
        """成功请求后推进参考演进，登记新版本摘要。"""
        nonlocal ref_config, next_ref_version
        ref_config = ref_apply(ref_config, operations)
        digest_at[next_ref_version] = config_digest(ref_config)
        next_ref_version += 1

    requests: list[dict] = []

    def add(request_id: str, package: dict, expect: dict) -> None:
        requests.append(
            {"tenant": TENANT, "request_id": request_id, "package": package,
             "expect": expect}
        )

    # r01：普通叶路径，单 publisher 即可，v0 -> v1
    r01_ops = [{"op": "set", "path": "/app/timeout", "value": 45}]
    add(
        "r01-app-timeout",
        make_package(0, r01_ops, ["alice"], digest_at[0]),
        {"ok": True, "status": "COMMITTED", "version": 1,
         "affected_leaves": ["/app/timeout"]},
    )
    record_success(r01_ops)

    # r02：签名被篡改 -> 验签失败
    add(
        "r02-bad-signature",
        make_package(1, [{"op": "set", "path": "/app/timeout", "value": 60}],
                     ["alice"], digest_at[1], tamper_signature=True),
        {"ok": False, "error_code": "SIGNATURE_INVALID", "version": None},
    )

    # r03：高敏叶路径仅一个 publisher -> 双角色拒绝
    add(
        "r03-sensitive-single",
        make_package(1, [{"op": "set", "path": "/security/mode", "value": "enforce"}],
                     ["carol"], digest_at[1]),
        {"ok": False,
         "error_code": "HIGH_SENSITIVE_DUAL_CONTROL_REQUIRED", "version": None},
    )

    # r04：高敏叶路径 publisher+reviewer 双角色，v1 -> v2
    r04_ops = [{"op": "set", "path": "/security/mode", "value": "enforce"}]
    add(
        "r04-sensitive-dual",
        make_package(1, r04_ops, ["carol", "bob"], digest_at[1]),
        {"ok": True, "status": "COMMITTED", "version": 2,
         "affected_leaves": ["/security/mode"]},
    )
    record_success(r04_ops)

    # r05：数组下标赋值被禁止（数组整体是叶）
    add(
        "r05-array-index",
        make_package(2, [{"op": "set", "path": "/app/tags/0", "value": "blue"}],
                     ["alice"], digest_at[2]),
        {"ok": False, "error_code": "ARRAY_INDEX_FORBIDDEN", "version": None},
    )

    # r06：数组整体替换为叶，单 publisher，v2 -> v3
    r06_ops = [{"op": "set", "path": "/app/tags",
                "value": ["stable", "blue"]}]
    r06_package = make_package(2, r06_ops, ["alice"], digest_at[2])
    add(
        "r06-array-replace",
        r06_package,
        {"ok": True, "status": "COMMITTED", "version": 3,
         "affected_leaves": ["/app/tags"]},
    )
    record_success(r06_ops)

    # r07：同 ID 同参数重放 -> 第一次持久化结果（v3，replayed）
    add(
        "r06-array-replace",
        r06_package,  # 与第一次完全相同的包
        {"ok": True, "status": "COMMITTED", "version": 3, "replayed": True},
    )

    # r08：同 ID 异参 -> 拒绝（不产生新版本）
    add(
        "r06-array-replace",
        make_package(2, [{"op": "set", "path": "/app/tags",
                          "value": ["different"]}],
                     ["alice"], digest_at[2]),
        {"ok": False, "error_code": "REQUEST_PARAM_MISMATCH", "version": None},
    )

    # r09：基准版本过期（当前 v3，包仍绑定 v2）-> 拒绝
    add(
        "r09-stale-base",
        make_package(2, [{"op": "set", "path": "/app/timeout", "value": 90}],
                     ["alice"], digest_at[2]),
        {"ok": False, "error_code": "BASE_VERSION_MISMATCH", "version": None},
    )

    # r10：创建具体键（嵌套父对象已存在），v3 -> v4
    r10_ops = [{"op": "set", "path": "/features/beta", "value": True}]
    add(
        "r10-create-key",
        make_package(3, r10_ops, ["alice"], digest_at[3]),
        {"ok": True, "status": "COMMITTED", "version": 4,
         "affected_leaves": ["/features/beta"]},
    )
    record_success(r10_ops)

    # r11：创建嵌套键但中间路径不存在 -> 拒绝
    add(
        "r11-create-deep-missing",
        make_package(4, [{"op": "set", "path": "/features/sub/flag", "value": True}],
                     ["alice"], digest_at[4]),
        {"ok": False, "error_code": "POINTER_NOT_FOUND", "version": None},
    )

    # r12：schema 违规（枚举值非法）-> 拒绝
    add(
        "r12-schema-enum",
        make_package(4, [{"op": "set", "path": "/security/mode",
                          "value": "breaking"}],
                     ["carol", "bob"], digest_at[4]),
        {"ok": False, "error_code": "SCHEMA_VIOLATION", "version": None},
    )

    # r13：删除整个高敏对象 tokens，叶路径并集来自原子树；需双角色，v4 -> v5
    r13_ops = [{"op": "delete", "path": "/security/tokens"}]
    add(
        "r13-delete-object",
        make_package(4, r13_ops, ["carol", "bob"], digest_at[4]),
        {"ok": True, "status": "COMMITTED", "version": 5,
         "affected_leaves": ["/security/tokens/primary"]},
    )
    record_success(r13_ops)

    # r14：敏感父对象整体替换，原树+新树叶路径并集均须双角色授权，v5 -> v6
    r14_ops = [{"op": "set", "path": "/security/tokens",
                "value": {"primary": "k-new", "secondary": "k-backup"}}]
    add(
        "r14-replace-sensitive-parent",
        make_package(5, r14_ops, ["carol", "bob"], digest_at[5]),
        {"ok": True, "status": "COMMITTED", "version": 6,
         "affected_leaves": [
             "/security/tokens/primary",
             "/security/tokens/secondary",
         ]},
    )
    record_success(r14_ops)

    # r15：作用域不足（dave 仅覆盖 /app/name，改 timeout 被拒）
    add(
        "r15-scope-denied",
        make_package(6, [{"op": "set", "path": "/app/timeout", "value": 100}],
                     ["dave"], digest_at[6]),
        {"ok": False, "error_code": "SCOPE_DENIED", "version": None},
    )

    # r16：未知签名者
    unknown_pkg = make_package(
        6, [{"op": "set", "path": "/app/timeout", "value": 100}],
        ["alice"], digest_at[6],
    )
    unknown_pkg["signatures"] = [
        {"identity": "mallory",
         "signature": sign(package_digest(unknown_pkg), "secret-mallory")}
    ]
    add(
        "r16-unknown-signer",
        unknown_pkg,
        {"ok": False, "error_code": "UNKNOWN_SIGNER", "version": None},
    )

    # r17：目标不匹配
    add(
        "r17-target-mismatch",
        make_package(6, [{"op": "set", "path": "/app/timeout", "value": 100}],
                     ["alice"], digest_at[6], target="other-config"),
        {"ok": False, "error_code": "TARGET_MISMATCH", "version": None},
    )

    scenario = {
        "scenario_name": "offline-config-publisher-cases",
        "description": "离线配置发布器可重放场景；expect 为手工确定的独立判定",
        "bootstrap": {
            "tenant": TENANT,
            "target": TARGET,
            "schema": SCHEMA,
            "sensitive_prefixes": SENSITIVE_PREFIXES,
            "initial_config": INITIAL_CONFIG,
            "initial_config_digest": v0_digest,
            "signers": SIGNERS,
        },
        "requests": requests,
    }

    out_path = Path(__file__).resolve().parents[1] / "cases.json"
    with open(out_path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(scenario, fh, ensure_ascii=False, indent=2, sort_keys=True)
        fh.write("\n")
    print(f"已生成 {out_path}（{len(requests)} 个请求，参考版本 0..{next_ref_version - 1}）")


if __name__ == "__main__":
    main()
