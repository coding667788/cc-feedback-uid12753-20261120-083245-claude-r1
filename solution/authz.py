"""授权：作用域覆盖、高敏路径双角色、模拟签名核验。

规则（与题目逐条对应）：
  * 每项操作最终受影响的每个叶路径都必须得到授权；
  * 作用域是 JSON Pointer 前缀集合，覆盖“自身及其全部子树”；
  * 高敏路径前缀下的叶路径要求两个相互独立的角色：一人发布
    （publisher）、一人复核（reviewer），两个签名都绑定完整包摘要；
  * 普通叶路径至少一个当前仍有效、且作用域覆盖该叶路径的签名者；
  * 签名者状态（启用/停用）与作用域以**发布事务内的当前值**为准，
    预检通过后被撤权的身份不得继续发布。
"""

from __future__ import annotations

from dataclasses import dataclass

from .canonical import verify_signature
from .errors import (
    ERR_HIGH_SENSITIVE_DUAL,
    ERR_ROLE_INVALID,
    ERR_SCOPE_DENIED,
    ERR_SIGNATURE,
    ERR_SIGNER_INACTIVE,
    ERR_UNKNOWN_SIGNER,
    PublishError,
)
from .jsonptr import parse, to_string


@dataclass(frozen=True)
class Signer:
    identity: str
    role: str  # publisher | reviewer
    scopes: tuple[str, ...]
    secret: str
    active: bool


def _scope_tokens(scopes: tuple[str, ...]) -> list[list[str]]:
    return [parse(scope) for scope in scopes]


def scope_covers(scopes: tuple[str, ...], leaf: str) -> bool:
    """作用域前缀覆盖判定：作用域路径是叶路径的前缀（按 token 比较）。"""
    leaf_tokens = parse(leaf)
    for scope_tokens in _scope_tokens(scopes):
        if leaf_tokens[: len(scope_tokens)] == scope_tokens:
            return True
    return False


def is_sensitive(leaf: str, sensitive_prefixes: tuple[str, ...]) -> bool:
    """叶路径是否落在任一高敏前缀子树内。"""
    leaf_tokens = parse(leaf)
    for prefix in sensitive_prefixes:
        prefix_tokens = parse(prefix)
        if leaf_tokens[: len(prefix_tokens)] == prefix_tokens:
            return True
    return False


def check_signatures(package: dict, digest_hex: str, signers: dict[str, Signer]) -> list[Signer]:
    """核验包上的全部签名，返回去重后的有效签名者（顺序按包中出现顺序）。"""
    raw_signatures = package.get("signatures")
    if not isinstance(raw_signatures, list):
        raise PublishError(ERR_SIGNATURE, "signatures 必须是数组")
    accepted: list[Signer] = []
    seen: set[str] = set()
    for item in raw_signatures:
        if not isinstance(item, dict) or "identity" not in item or "signature" not in item:
            raise PublishError(ERR_SIGNATURE, "签名项必须包含 identity 与 signature")
        identity = item["identity"]
        signer = signers.get(identity)
        if signer is None:
            raise PublishError(ERR_UNKNOWN_SIGNER, f"未知签名者: {identity}")
        if not signer.active:
            raise PublishError(
                ERR_SIGNER_INACTIVE, f"签名者已被停用/撤权: {identity}"
            )
        verify_signature(digest_hex, signer.secret, item["signature"])
        if identity not in seen:
            seen.add(identity)
            accepted.append(signer)
    return accepted


def authorize(
    affected_leaves: set[str],
    signers: list[Signer],
    sensitive_prefixes: tuple[str, ...],
) -> None:
    """对受影响叶路径并集做最终授权判定。"""
    if not affected_leaves:
        # 无叶路径可授权只可能来自空操作包，包结构校验阶段已拒绝
        raise PublishError(ERR_SCOPE_DENIED, "变更包没有任何受影响叶路径")
    if not signers:
        raise PublishError(ERR_SCOPE_DENIED, "变更包没有任何签名，无法授权")

    publishers = [s for s in signers if s.role == "publisher"]
    if not publishers:
        raise PublishError(ERR_ROLE_INVALID, "至少需要一名 publisher 角色签名")
    invalid_roles = {s.identity: s.role for s in signers if s.role not in ("publisher", "reviewer")}
    if invalid_roles:
        raise PublishError(ERR_ROLE_INVALID, f"存在非法角色: {invalid_roles}")

    for leaf in sorted(affected_leaves):
        covering = [s for s in signers if scope_covers(s.scopes, leaf)]
        if not covering:
            raise PublishError(
                ERR_SCOPE_DENIED, f"叶路径 {leaf} 未被任何签名者作用域覆盖"
            )
        if is_sensitive(leaf, sensitive_prefixes):
            cover_pub = [s for s in covering if s.role == "publisher"]
            cover_rev = [s for s in covering if s.role == "reviewer"]
            if not cover_pub or not cover_rev:
                raise PublishError(
                    ERR_HIGH_SENSITIVE_DUAL,
                    f"高敏叶路径 {leaf} 需要 publisher 与 reviewer 两个独立角色"
                    "（一人发布、一人复核），且二者作用域均覆盖该路径",
                )
            # 两个独立角色：身份天然不同（角色互斥），再次显式断言
            if cover_pub[0].identity == cover_rev[0].identity:
                raise PublishError(
                    ERR_HIGH_SENSITIVE_DUAL,
                    f"高敏叶路径 {leaf} 的发布与复核不得为同一身份",
                )


def describe_coverage(
    affected_leaves: set[str],
    signers: list[Signer],
    sensitive_prefixes: tuple[str, ...],
) -> dict:
    """生成可读的覆盖明细，供回执与测试排障使用（不参与安全判定）。"""
    detail: dict[str, dict] = {}
    for leaf in sorted(affected_leaves):
        detail[leaf] = {
            "sensitive": is_sensitive(leaf, sensitive_prefixes),
            "covered_by": sorted(
                s.identity for s in signers if scope_covers(s.scopes, leaf)
            ),
        }
    return detail


# 避免静态检查工具抱怨 to_string 仅用于调试导出
__all__ = [
    "Signer",
    "scope_covers",
    "is_sensitive",
    "check_signatures",
    "authorize",
    "describe_coverage",
    "to_string",
]
