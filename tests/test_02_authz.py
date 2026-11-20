"""作用域覆盖、模拟验签、高敏双角色与撤权的独立断言。"""

import unittest

from solution import authz
from solution.authz import Signer
from solution.canonical import package_digest, sign
from solution.errors import (
    ERR_HIGH_SENSITIVE_DUAL,
    ERR_ROLE_INVALID,
    ERR_SCOPE_DENIED,
    ERR_SIGNATURE,
    ERR_SIGNER_INACTIVE,
    ERR_UNKNOWN_SIGNER,
    PublishError,
)
from tests._helpers import make_package, SECRETS, SENSITIVE_PREFIXES


def _signer(identity, role, scopes, active=True):
    return Signer(
        identity=identity, role=role, scopes=tuple(scopes),
        secret=SECRETS[identity], active=active,
    )


class ScopeTest(unittest.TestCase):
    def test_prefix_coverage_semantics(self):
        scopes = ("/app",)
        self.assertTrue(authz.scope_covers(scopes, "/app/timeout"))
        self.assertTrue(authz.scope_covers(scopes, "/app"))
        # 仅按 token 前缀：/apple 不被 /app 覆盖
        self.assertFalse(authz.scope_covers(scopes, "/apple"))
        self.assertFalse(authz.scope_covers(scopes, "/security/mode"))
        self.assertTrue(authz.scope_covers(("",), "/anything"))

    def test_sensitive_detection(self):
        self.assertTrue(authz.is_sensitive("/security/mode", SENSITIVE_PREFIXES))
        self.assertTrue(authz.is_sensitive("/security", SENSITIVE_PREFIXES))
        self.assertFalse(authz.is_sensitive("/app/timeout", SENSITIVE_PREFIXES))


class SignatureTest(unittest.TestCase):
    def setUp(self):
        self.signers = {
            "alice": _signer("alice", "publisher", ["/app"]),
            "bob": _signer("bob", "reviewer", ["/security"]),
        }
        self.package = make_package(
            0, [{"op": "set", "path": "/app/timeout", "value": 1}],
            ["alice"], "digest-placeholder",
        )
        self.digest = package_digest(self.package)

    def test_valid_signature_accepted(self):
        accepted = authz.check_signatures(self.package, self.digest, self.signers)
        self.assertEqual([s.identity for s in accepted], ["alice"])

    def test_tampered_signature_rejected(self):
        self.package["signatures"][0]["signature"] = "f" * 64
        with self.assertRaises(PublishError) as ctx:
            authz.check_signatures(self.package, self.digest, self.signers)
        self.assertEqual(ctx.exception.code, ERR_SIGNATURE)

    def test_tampered_package_rejected(self):
        # 包内容被改 -> 摘要变化 -> 原签名不再匹配
        self.package["operations"][0]["value"] = 2
        with self.assertRaises(PublishError) as ctx:
            authz.check_signatures(
                self.package, package_digest(self.package), self.signers
            )
        self.assertEqual(ctx.exception.code, ERR_SIGNATURE)

    def test_unknown_signer(self):
        self.package["signatures"] = [
            {"identity": "mallory", "signature": "0" * 64}
        ]
        with self.assertRaises(PublishError) as ctx:
            authz.check_signatures(self.package, self.digest, self.signers)
        self.assertEqual(ctx.exception.code, ERR_UNKNOWN_SIGNER)

    def test_inactive_signer_rejected(self):
        signers = dict(self.signers)
        signers["alice"] = _signer("alice", "publisher", ["/app"], active=False)
        with self.assertRaises(PublishError) as ctx:
            authz.check_signatures(self.package, self.digest, signers)
        self.assertEqual(ctx.exception.code, ERR_SIGNER_INACTIVE)


class AuthorizeTest(unittest.TestCase):
    def setUp(self):
        self.alice = _signer("alice", "publisher", ["/app", "/features"])
        self.bob = _signer("bob", "reviewer", ["/security", "/app"])
        self.carol = _signer("carol", "publisher", ["/security"])

    def test_normal_leaf_single_publisher_ok(self):
        authz.authorize({"/app/timeout"}, [self.alice], SENSITIVE_PREFIXES)

    def test_uncovered_leaf_denied(self):
        dave = _signer("dave", "publisher", ["/app/name"])
        with self.assertRaises(PublishError) as ctx:
            authz.authorize({"/app/timeout"}, [dave], SENSITIVE_PREFIXES)
        self.assertEqual(ctx.exception.code, ERR_SCOPE_DENIED)

    def test_sensitive_needs_two_roles(self):
        with self.assertRaises(PublishError) as ctx:
            authz.authorize({"/security/mode"}, [self.carol], SENSITIVE_PREFIXES)
        self.assertEqual(ctx.exception.code, ERR_HIGH_SENSITIVE_DUAL)

    def test_sensitive_dual_control_ok(self):
        authz.authorize(
            {"/security/mode"}, [self.carol, self.bob], SENSITIVE_PREFIXES
        )

    def test_sensitive_reviewer_without_scope_denied(self):
        # reviewer 存在但作用域不覆盖该叶 -> 仍是双角色失败
        bob_limited = _signer("bob", "reviewer", ["/app"])
        with self.assertRaises(PublishError) as ctx:
            authz.authorize(
                {"/security/mode"}, [self.carol, bob_limited], SENSITIVE_PREFIXES
            )
        self.assertEqual(ctx.exception.code, ERR_HIGH_SENSITIVE_DUAL)

    def test_no_publisher_role_rejected(self):
        with self.assertRaises(PublishError) as ctx:
            authz.authorize({"/app/timeout"}, [self.bob], SENSITIVE_PREFIXES)
        self.assertEqual(ctx.exception.code, ERR_ROLE_INVALID)

    def test_mixed_union_every_leaf_checked(self):
        # 同时含普通叶与高敏叶：普通叶一人即可，高敏叶必须双角色
        with self.assertRaises(PublishError) as ctx:
            authz.authorize(
                {"/app/timeout", "/security/mode"},
                [self.alice, self.carol], SENSITIVE_PREFIXES,
            )
        self.assertEqual(ctx.exception.code, ERR_HIGH_SENSITIVE_DUAL)
        authz.authorize(
            {"/app/timeout", "/security/mode"},
            [self.alice, self.carol, self.bob], SENSITIVE_PREFIXES,
        )


if __name__ == "__main__":
    unittest.main()
