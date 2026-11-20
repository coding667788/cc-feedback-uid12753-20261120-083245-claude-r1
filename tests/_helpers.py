"""测试共享夹具：临时目录、独立造包/造签名、独立参考实现。

夹具只复用 solution.canonical 的哈希/HMAC 原语（测试夹具自身能力）；
期望配置与期望摘要由本文件的独立参考函数计算，不读取被测发布结果。
"""

from __future__ import annotations

import copy
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

# 让 tests 目录在 python -m unittest discover 下也能导入 solution
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from solution.canonical import config_digest, package_digest, sign  # noqa: E402
from solution.store import Store  # noqa: E402

TENANT = "t1"
TARGET = "app-config"
SENSITIVE_PREFIXES = ["/security"]

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

SIGNERS = [
    {"identity": "alice", "role": "publisher",
     "scopes": ["/app", "/features"], "secret": "secret-alice", "active": True},
    {"identity": "bob", "role": "reviewer",
     "scopes": ["/security", "/app"], "secret": "secret-bob", "active": True},
    {"identity": "carol", "role": "publisher",
     "scopes": ["/security"], "secret": "secret-carol", "active": True},
    {"identity": "dave", "role": "publisher",
     "scopes": ["/app/name"], "secret": "secret-dave", "active": True},
]
SECRETS = {item["identity"]: item["secret"] for item in SIGNERS}


def make_package(
    base_version: int,
    operations: list[dict],
    signer_ids: list[str],
    base_config_digest: str,
    target: str = TARGET,
) -> dict:
    """夹具自行造包并用各自身份密钥签名（不经过被测发布逻辑）。"""
    package = {
        "target": target,
        "base_version": base_version,
        "config_digest": base_config_digest,
        "operations": operations,
        "signatures": [],
    }
    digest = package_digest(package)
    for identity in signer_ids:
        package["signatures"].append(
            {"identity": identity, "signature": sign(digest, SECRETS[identity])}
        )
    return package


def ref_apply(config: dict, operations: list[dict]) -> dict:
    """独立参考变更器：仅对象内 set/delete，用于独立计算期望配置。"""
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


def new_store(testcase: unittest.TestCase, busy_timeout_ms: int = 30000) -> tuple[Store, str]:
    """每个测试一个全新临时数据库。"""
    tmpdir = tempfile.mkdtemp(prefix="ocp-")
    testcase.addCleanup(_safe_rmtree, tmpdir)
    db_path = os.path.join(tmpdir, "publisher.sqlite3")
    store = Store(db_path, busy_timeout_ms=busy_timeout_ms)
    store.init_schema()
    store.bootstrap_tenant(
        tenant=TENANT,
        target=TARGET,
        schema=SCHEMA,
        sensitive_prefixes=SENSITIVE_PREFIXES,
        initial_config=INITIAL_CONFIG,
        signers=SIGNERS,
    )
    return store, db_path


def _safe_rmtree(path: str) -> None:
    import shutil

    shutil.rmtree(path, ignore_errors=True)


def dump_json(path: str | Path, value: dict) -> None:
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(value, fh, ensure_ascii=False)


def load_json(path: str | Path) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def initial_digest() -> str:
    return config_digest(INITIAL_CONFIG)
