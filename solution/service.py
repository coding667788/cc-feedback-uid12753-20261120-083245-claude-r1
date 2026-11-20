"""发布服务：预检、事务内重验、幂等请求、审计与崩溃屏障。

事务内重新验证（而不是复用预检结论）：
  1. 基准版本 == 当前发布指针版本；
  2. 基准规范配置摘要 == 基准快照摘要；
  3. 签名者当前作用域与启用状态（支持“预检后撤权”）；
  4. 全部签名仍绑定完整包摘要；
  5. 最终配置树通过 schema；
  6. request_id 与参数（包摘要）匹配幂等表。
恢复旧内容同样走完整流程并产生新版本，旧签名/旧前置条件不可复用。
"""

from __future__ import annotations

import json
from typing import Any

from . import authz, package as pkgmod
from .canonical import config_digest, package_digest
from .errors import (
    ERR_BASE_VERSION,
    ERR_CONFIG_HASH,
    ERR_REQUEST_PARAM_MISMATCH,
    ERR_TARGET_MISMATCH,
    ERR_UNKNOWN_TENANT,
    PublishError,
)
from .schema import validate as schema_validate
from .store import Store


class Hooks:
    """发布屏障钩子；默认实现什么都不做。"""

    def after_snapshot_before_commit(self, context: dict) -> None:
        """快照已写入写事务但尚未提交（崩溃点 A）。"""

    def after_commit(self, context: dict) -> None:
        """事务已提交、发布指针已更新（崩溃点 B）。"""


class NullHooks(Hooks):
    pass


class PublisherService:
    def __init__(self, store: Store, hooks: Hooks | None = None):
        self.store = store
        self.hooks = hooks or NullHooks()

    # ------------------------------------------------------------ 内部工具
    def _load_tenant(self, conn, tenant: str) -> dict:
        row = self.store.get_tenant(conn, tenant)
        if row is None:
            raise PublishError(ERR_UNKNOWN_TENANT, f"未知租户: {tenant}")
        return {
            "target": row["target"],
            "schema": json.loads(row["schema_json"]),
            "sensitive_prefixes": tuple(json.loads(row["sensitive_prefixes_json"])),
        }

    def _validate(self, conn, tenant: str, request_id: str, package: dict) -> dict:
        """全部确定性校验；返回发布所需的上下文（事务内外均可调用）。"""
        pkgmod.validate_shape(package)
        tenant_row = self._load_tenant(conn, tenant)

        if package["target"] != tenant_row["target"]:
            raise PublishError(
                ERR_TARGET_MISMATCH,
                f"包目标 {package['target']!r} 与租户绑定目标 "
                f"{tenant_row['target']!r} 不一致",
            )

        pointer_version = self.store.get_pointer_version(conn, tenant)
        if package["base_version"] != pointer_version:
            raise PublishError(
                ERR_BASE_VERSION,
                f"基准版本 {package['base_version']} 与当前发布版本 "
                f"{pointer_version} 不一致（旧前置条件不可复用）",
            )

        base_snapshot = self.store.get_snapshot(conn, tenant, pointer_version)
        if base_snapshot is None:  # 防御性：指针外键正常时不会发生
            raise PublishError(
                ERR_BASE_VERSION, f"基准快照缺失: 版本 {pointer_version}"
            )
        if package["config_digest"] != base_snapshot["config_digest"]:
            raise PublishError(
                ERR_CONFIG_HASH,
                "包绑定的规范配置摘要与基准快照摘要不一致，"
                "请基于当前版本重新制作变更包",
            )
        base_config = json.loads(base_snapshot["config_json"])

        digest = package_digest(package)
        signers = self.store.get_signers(conn, tenant)
        accepted = authz.check_signatures(package, digest, signers)

        new_config, affected = pkgmod.apply_operations(
            base_config, package["operations"]
        )
        authz.authorize(affected, accepted, tenant_row["sensitive_prefixes"])
        schema_validate(tenant_row["schema"], new_config)
        new_digest = config_digest(new_config)

        return {
            "tenant": tenant,
            "request_id": request_id,
            "package_digest": digest,
            "base_version": pointer_version,
            "new_config": new_config,
            "new_config_digest": new_digest,
            "affected_leaves": sorted(affected),
            "signer_identities": [s.identity for s in accepted],
            "coverage": authz.describe_coverage(
                affected, accepted, tenant_row["sensitive_prefixes"]
            ),
        }

    # ---------------------------------------------------------------- 预检
    def precheck(self, tenant: str, request_id: str, package: dict) -> dict:
        """只读预检：不落任何数据，返回若立即发布会得到的结果。"""
        conn = self.store.connect()
        try:
            context = self._validate(conn, tenant, request_id, package)
            return {
                "ok": True,
                "request_id": request_id,
                "would_publish_version": context["base_version"] + 1,
                "package_digest": context["package_digest"],
                "affected_leaves": context["affected_leaves"],
                "signer_identities": context["signer_identities"],
                "coverage": context["coverage"],
                "new_config_digest": context["new_config_digest"],
            }
        finally:
            conn.close()

    # ---------------------------------------------------------------- 发布
    def publish(self, tenant: str, request_id: str, package: dict) -> dict:
        """执行一次幂等发布，返回业务回执（失败也用回执表达）。

        时序保证：先 ``BEGIN IMMEDIATE`` 取得写锁，**再**在同一事务内做
        幂等判定与全部重验。这样并发发布者在拿到锁后看到的必是最新已提交
        状态，基准版本失效会在事务内被拒，而不会依赖锁外的旧快照。
        """
        try:
            pkgmod.validate_shape(package)
        except PublishError as exc:
            # 结构坏到无法计算包摘要时，无法做幂等键，直接给失败回执
            return self._failure_receipt(tenant, request_id, None, exc)

        digest = package_digest(package)
        conn = self.store.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")

            # 1) 事务内幂等判定（同 request_id 同租户）
            existing = self.store.get_request(conn, tenant, request_id)
            if existing is not None:
                if existing["package_digest"] != digest:
                    raise PublishError(
                        ERR_REQUEST_PARAM_MISMATCH,
                        f"request_id {request_id!r} 已用于不同参数的请求；"
                        "同 ID 异参一律拒绝",
                    )
                conn.commit()
                return {
                    "ok": existing["status"] == "COMMITTED",
                    "replayed": True,
                    "tenant": tenant,
                    "request_id": request_id,
                    "package_digest": digest,
                    **json.loads(existing["receipt_json"]),
                }

            # 2) 持写锁后的事务内完整重验
            try:
                context = self._validate(conn, tenant, request_id, package)
            except PublishError as exc:
                # 业务失败与业务状态分离：回滚快照/指针，仅把失败回执
                # 作为独立事务持久化（见 persist_failed_request）
                conn.rollback()
                conn.close()
                self.store.persist_failed_request(
                    tenant, request_id, digest,
                    {"status": "FAILED", "error": exc.to_dict()},
                )
                return {
                    "ok": False,
                    "replayed": False,
                    "tenant": tenant,
                    "request_id": request_id,
                    "package_digest": digest,
                    "status": "FAILED",
                    "error": exc.to_dict(),
                }

            # 3) 同一写事务：快照 + 指针 + 请求回执 + 审计，原子提交
            next_version = context["base_version"] + 1
            self.store.insert_snapshot(
                conn, tenant, next_version,
                context["new_config"], context["new_config_digest"], request_id,
            )
            self.store.advance_pointer(conn, tenant, next_version)
            receipt = {
                "status": "COMMITTED",
                "version": next_version,
                "base_version": context["base_version"],
                "new_config_digest": context["new_config_digest"],
                "affected_leaves": context["affected_leaves"],
                "signer_identities": context["signer_identities"],
            }
            self.store.insert_request(
                conn, tenant, request_id, digest, "COMMITTED", next_version, receipt
            )
            self.store.append_audit(
                conn, tenant, request_id, next_version, "PUBLISH",
                {
                    "package_digest": digest,
                    "affected_leaves": context["affected_leaves"],
                    "signer_identities": context["signer_identities"],
                },
            )
            hook_context = {
                "tenant": tenant,
                "request_id": request_id,
                "version": next_version,
                "package_digest": digest,
            }
            # 崩溃点 A：快照已在事务内写入，尚未 commit
            self.hooks.after_snapshot_before_commit(hook_context)
            conn.commit()
            # 崩溃点 B：提交已完成
            self.hooks.after_commit(hook_context)
            return {
                "ok": True,
                "replayed": False,
                "tenant": tenant,
                "request_id": request_id,
                "package_digest": digest,
                **receipt,
            }
        except PublishError as exc:
            # 幂等异参等“请求级拒绝”：回滚且不抢占 request_id
            conn.rollback()
            return {
                "ok": False,
                "replayed": False,
                "tenant": tenant,
                "request_id": request_id,
                "package_digest": digest,
                "status": "REJECTED",
                "error": exc.to_dict(),
            }
        finally:
            conn.close()

    def _failure_receipt(
        self, tenant: str, request_id: str, digest: str | None, exc: PublishError
    ) -> dict:
        return {
            "ok": False,
            "replayed": False,
            "tenant": tenant,
            "request_id": request_id,
            "package_digest": digest,
            "status": "FAILED",
            "error": exc.to_dict(),
        }

    # ---------------------------------------------------------------- 只读
    def inspect(self, tenant: str) -> dict:
        """读者视角的完整状态：当前指针、全部快照、请求与审计。"""
        conn = self.store.connect()
        try:
            self._load_tenant(conn, tenant)
            pointer = self.store.get_pointer_version(conn, tenant)
            requests = [
                dict(row)
                for row in conn.execute(
                    "SELECT request_id, package_digest, status, version,"
                    " receipt_json FROM idempotency_requests"
                    " WHERE tenant=? ORDER BY rowid",
                    (tenant,),
                ).fetchall()
            ]
        finally:
            conn.close()
        published = self.store.read_published(tenant)
        return {
            "tenant": tenant,
            "pointer_version": pointer,
            "published": published,
            "snapshots": self.store.list_snapshots(tenant),
            "requests": requests,
            "audit": self.store.list_audit(tenant),
        }
