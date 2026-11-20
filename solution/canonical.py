"""规范化 JSON、包摘要与模拟验签（仅标准库 hashlib/hmac）。

摘要规则：
  * 规范化序列化 ``json.dumps(..., sort_keys=True, separators=(",", ":"),
    ensure_ascii=False)``，保证键序、空白不影响摘要；
  * 包摘要覆盖目标、基准版本、规范配置摘要（canonical config hash）以及
    全部有序操作，签名只绑定这份完整包摘要；
  * 模拟签名采用 HMAC-SHA256（密钥即身份密钥），仅作离线演示，不声称
    具备非对称密码学性质。
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

from .errors import ERR_SIGNATURE, PublishError


def canonical_dumps(value: Any) -> str:
    """确定性 JSON 序列化：键排序、无多余空白、保留 Unicode。"""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )


def sha256_hex(value: Any) -> str:
    """对任意可 JSON 化的值计算规范化 SHA-256 十六进制摘要。"""
    return hashlib.sha256(canonical_dumps(value).encode("utf-8")).hexdigest()


def config_digest(config: Any) -> str:
    """规范配置摘要：对整棵配置树做规范化哈希。"""
    return sha256_hex(config)


def package_digest(package: dict) -> str:
    """完整变更包摘要。

    参与摘要的字段固定为 target/base_version/config_digest/operations，
    signatures 字段不参与（否则签名会自引用）。
    """
    payload = {
        "target": package["target"],
        "base_version": package["base_version"],
        "config_digest": package["config_digest"],
        "operations": package["operations"],
    }
    return sha256_hex(payload)


def sign(digest_hex: str, secret: str) -> str:
    """用身份密钥对包摘要做 HMAC-SHA256，返回十六进制签名。"""
    return hmac.new(
        secret.encode("utf-8"),
        digest_hex.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def verify_signature(digest_hex: str, secret: str, signature: str) -> None:
    """常数时间校验签名，失败抛 :class:`PublishError`。"""
    expected = sign(digest_hex, secret)
    if not hmac.compare_digest(expected, signature):
        raise PublishError(
            ERR_SIGNATURE, "签名与完整包摘要不匹配，或包内容被篡改"
        )
