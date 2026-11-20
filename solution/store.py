"""SQLite 存储层：不可变快照、发布指针、幂等请求、审计与签名者注册表。

设计要点：
  * WAL 模式 + ``busy_timeout``：读写不互斥，崩溃后读者也不会读到
    未提交的中间状态；
  * ``config_snapshots`` 由触发器禁止 UPDATE/DELETE，形成只追加不可变快照；
  * 发布指针 ``publish_pointer`` 与新快照、请求回执、审计在**同一个写事务**
    里提交，事务外任何人只能看到“旧版本”或“新版本”，没有中间态；
  * 签名者当前作用域/启用状态存于 ``signers`` 表，发布事务内实时读取，
    支撑“预检后撤权”场景。
"""

from __future__ import annotations

import json
import sqlite3
import time
from contextlib import contextmanager
from typing import Any, Iterator

from .canonical import canonical_dumps
from .errors import ERR_STORAGE, PublishError

_SCHEMA_SQL = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS tenants (
    tenant                 TEXT PRIMARY KEY,
    target                 TEXT NOT NULL,
    schema_json            TEXT NOT NULL,
    sensitive_prefixes_json TEXT NOT NULL,
    created_at             REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS signers (
    tenant      TEXT NOT NULL,
    identity    TEXT NOT NULL,
    role        TEXT NOT NULL,
    scopes_json TEXT NOT NULL,
    secret      TEXT NOT NULL,
    active      INTEGER NOT NULL,
    PRIMARY KEY (tenant, identity),
    FOREIGN KEY (tenant) REFERENCES tenants(tenant)
);

CREATE TABLE IF NOT EXISTS config_snapshots (
    tenant             TEXT NOT NULL,
    version            INTEGER NOT NULL,
    config_json        TEXT NOT NULL,
    config_digest      TEXT NOT NULL,
    created_request_id TEXT,
    created_at         REAL NOT NULL,
    PRIMARY KEY (tenant, version),
    FOREIGN KEY (tenant) REFERENCES tenants(tenant)
);

CREATE TRIGGER IF NOT EXISTS trg_snapshot_no_update
BEFORE UPDATE ON config_snapshots
BEGIN
    SELECT RAISE(ABORT, 'config_snapshots 是不可变快照，禁止 UPDATE');
END;

CREATE TRIGGER IF NOT EXISTS trg_snapshot_no_delete
BEFORE DELETE ON config_snapshots
BEGIN
    SELECT RAISE(ABORT, 'config_snapshots 是不可变快照，禁止 DELETE');
END;

CREATE TABLE IF NOT EXISTS publish_pointer (
    tenant     TEXT PRIMARY KEY,
    version    INTEGER NOT NULL,
    updated_at REAL NOT NULL,
    FOREIGN KEY (tenant, version) REFERENCES config_snapshots(tenant, version)
);

CREATE TABLE IF NOT EXISTS idempotency_requests (
    tenant         TEXT NOT NULL,
    request_id     TEXT NOT NULL,
    package_digest TEXT NOT NULL,
    status         TEXT NOT NULL,
    version        INTEGER,
    receipt_json   TEXT NOT NULL,
    created_at     REAL NOT NULL,
    PRIMARY KEY (tenant, request_id)
);

CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant      TEXT NOT NULL,
    request_id  TEXT,
    version     INTEGER,
    event       TEXT NOT NULL,
    detail_json TEXT NOT NULL,
    created_at  REAL NOT NULL
);

CREATE TRIGGER IF NOT EXISTS trg_audit_no_update
BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log 只可追加，禁止 UPDATE');
END;

CREATE TRIGGER IF NOT EXISTS trg_audit_no_delete
BEFORE DELETE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log 只可追加，禁止 DELETE');
END;
"""


def _dumps(value: Any) -> str:
    return canonical_dumps(value)


class Store:
    """单个 SQLite 文件上的全部持久化操作。"""

    def __init__(self, path: str, busy_timeout_ms: int = 30000):
        self.path = path
        self.busy_timeout_ms = busy_timeout_ms

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=self.busy_timeout_ms / 1000)
        conn.row_factory = sqlite3.Row
        conn.execute(f"PRAGMA busy_timeout={int(self.busy_timeout_ms)}")
        conn.execute("PRAGMA foreign_keys=ON")
        # 显式事务管理，BEGIN IMMEDIATE 由服务层控制
        conn.isolation_level = None
        return conn

    def init_schema(self) -> None:
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.executescript(_SCHEMA_SQL)
            conn.commit()
        except sqlite3.Error as exc:
            conn.rollback()
            raise PublishError(ERR_STORAGE, f"初始化数据库失败: {exc}") from exc
        finally:
            conn.close()

    # ------------------------------------------------------------------ 租户
    def bootstrap_tenant(
        self,
        tenant: str,
        target: str,
        schema: dict,
        sensitive_prefixes: list[str],
        initial_config: Any,
        signers: list[dict],
    ) -> None:
        """创建租户、签名者、版本 0 快照与初始发布指针（单事务，幂等）。"""
        from .authz import Signer  # 避免模块级循环导入
        from .canonical import config_digest

        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            existing = conn.execute(
                "SELECT tenant FROM tenants WHERE tenant=?", (tenant,)
            ).fetchone()
            if existing is not None:
                conn.commit()
                return
            now = time.time()
            conn.execute(
                "INSERT INTO tenants(tenant, target, schema_json,"
                " sensitive_prefixes_json, created_at) VALUES (?,?,?,?,?)",
                (tenant, target, _dumps(schema), _dumps(sensitive_prefixes), now),
            )
            for item in signers:
                signer = Signer(
                    identity=item["identity"],
                    role=item["role"],
                    scopes=tuple(item["scopes"]),
                    secret=item["secret"],
                    active=bool(item.get("active", True)),
                )
                conn.execute(
                    "INSERT INTO signers(tenant, identity, role, scopes_json,"
                    " secret, active) VALUES (?,?,?,?,?,?)",
                    (
                        tenant,
                        signer.identity,
                        signer.role,
                        _dumps(list(signer.scopes)),
                        signer.secret,
                        1 if signer.active else 0,
                    ),
                )
            digest = config_digest(initial_config)
            conn.execute(
                "INSERT INTO config_snapshots(tenant, version, config_json,"
                " config_digest, created_request_id, created_at)"
                " VALUES (?,?,?,?,?,?)",
                (tenant, 0, _dumps(initial_config), digest, None, now),
            )
            conn.execute(
                "INSERT INTO publish_pointer(tenant, version, updated_at)"
                " VALUES (?,?,?)",
                (tenant, 0, now),
            )
            conn.execute(
                "INSERT INTO audit_log(tenant, request_id, version, event,"
                " detail_json, created_at) VALUES (?,?,?,?,?,?)",
                (tenant, None, 0, "BOOTSTRAP", _dumps({"digest": digest}), now),
            )
            conn.commit()
        except sqlite3.Error as exc:
            conn.rollback()
            raise PublishError(ERR_STORAGE, f"租户初始化失败: {exc}") from exc
        finally:
            conn.close()

    # ------------------------------------------------------------------ 读取
    def get_tenant(self, conn: sqlite3.Connection, tenant: str) -> sqlite3.Row | None:
        return conn.execute(
            "SELECT * FROM tenants WHERE tenant=?", (tenant,)
        ).fetchone()

    def get_signers(self, conn: sqlite3.Connection, tenant: str) -> dict[str, "Signer"]:
        from .authz import Signer

        rows = conn.execute(
            "SELECT identity, role, scopes_json, secret, active"
            " FROM signers WHERE tenant=?",
            (tenant,),
        ).fetchall()
        return {
            row["identity"]: Signer(
                identity=row["identity"],
                role=row["role"],
                scopes=tuple(json.loads(row["scopes_json"])),
                secret=row["secret"],
                active=bool(row["active"]),
            )
            for row in rows
        }

    def get_snapshot(
        self, conn: sqlite3.Connection, tenant: str, version: int
    ) -> sqlite3.Row | None:
        return conn.execute(
            "SELECT * FROM config_snapshots WHERE tenant=? AND version=?",
            (tenant, version),
        ).fetchone()

    def get_pointer_version(self, conn: sqlite3.Connection, tenant: str) -> int:
        row = conn.execute(
            "SELECT version FROM publish_pointer WHERE tenant=?", (tenant,)
        ).fetchone()
        if row is None:
            raise PublishError(ERR_STORAGE, f"租户 {tenant} 缺少发布指针")
        return int(row["version"])

    def get_request(
        self, conn: sqlite3.Connection, tenant: str, request_id: str
    ) -> sqlite3.Row | None:
        return conn.execute(
            "SELECT * FROM idempotency_requests WHERE tenant=? AND request_id=?",
            (tenant, request_id),
        ).fetchone()

    def read_published(self, tenant: str) -> dict:
        """独立连接读取当前已发布版本（读者视角，永不看到未提交数据）。"""
        conn = self.connect()
        try:
            row = conn.execute(
                "SELECT p.version, s.config_json, s.config_digest"
                " FROM publish_pointer p"
                " JOIN config_snapshots s"
                " ON s.tenant=p.tenant AND s.version=p.version"
                " WHERE p.tenant=?",
                (tenant,),
            ).fetchone()
            if row is None:
                raise PublishError(ERR_STORAGE, f"租户 {tenant} 尚无已发布配置")
            return {
                "version": int(row["version"]),
                "config": json.loads(row["config_json"]),
                "config_digest": row["config_digest"],
            }
        finally:
            conn.close()

    def list_snapshots(self, tenant: str) -> list[dict]:
        conn = self.connect()
        try:
            rows = conn.execute(
                "SELECT version, config_digest, created_request_id, created_at"
                " FROM config_snapshots WHERE tenant=? ORDER BY version",
                (tenant,),
            ).fetchall()
            return [dict(row) for row in rows]
        finally:
            conn.close()

    def list_audit(self, tenant: str) -> list[dict]:
        conn = self.connect()
        try:
            rows = conn.execute(
                "SELECT id, request_id, version, event, detail_json, created_at"
                " FROM audit_log WHERE tenant=? ORDER BY id",
                (tenant,),
            ).fetchall()
            return [dict(row) for row in rows]
        finally:
            conn.close()

    # ------------------------------------------------------------------ 变更
    def set_signer_active(
        self, conn: sqlite3.Connection, tenant: str, identity: str, active: bool
    ) -> None:
        cur = conn.execute(
            "UPDATE signers SET active=? WHERE tenant=? AND identity=?",
            (1 if active else 0, tenant, identity),
        )
        if cur.rowcount != 1:
            raise PublishError(ERR_STORAGE, f"签名者不存在: {identity}")

    def insert_snapshot(
        self,
        conn: sqlite3.Connection,
        tenant: str,
        version: int,
        config: Any,
        digest: str,
        request_id: str,
    ) -> None:
        conn.execute(
            "INSERT INTO config_snapshots(tenant, version, config_json,"
            " config_digest, created_request_id, created_at)"
            " VALUES (?,?,?,?,?,?)",
            (tenant, version, _dumps(config), digest, request_id, time.time()),
        )

    def advance_pointer(
        self, conn: sqlite3.Connection, tenant: str, version: int
    ) -> None:
        conn.execute(
            "UPDATE publish_pointer SET version=?, updated_at=? WHERE tenant=?",
            (version, time.time(), tenant),
        )

    def insert_request(
        self,
        conn: sqlite3.Connection,
        tenant: str,
        request_id: str,
        package_digest: str,
        status: str,
        version: int | None,
        receipt: dict,
    ) -> None:
        conn.execute(
            "INSERT INTO idempotency_requests(tenant, request_id, package_digest,"
            " status, version, receipt_json, created_at) VALUES (?,?,?,?,?,?,?)",
            (
                tenant,
                request_id,
                package_digest,
                status,
                version,
                _dumps(receipt),
                time.time(),
            ),
        )

    def persist_failed_request(
        self,
        tenant: str,
        request_id: str,
        package_digest: str,
        receipt: dict,
    ) -> None:
        """业务失败回执独立成事务持久化，与“业务状态”（快照/指针）分离。"""
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "INSERT OR IGNORE INTO idempotency_requests(tenant, request_id,"
                " package_digest, status, version, receipt_json, created_at)"
                " VALUES (?,?,?,?,?,?,?)",
                (
                    tenant,
                    request_id,
                    package_digest,
                    "FAILED",
                    None,
                    _dumps(receipt),
                    time.time(),
                ),
            )
            conn.commit()
        except sqlite3.Error as exc:
            conn.rollback()
            raise PublishError(ERR_STORAGE, f"失败回执持久化失败: {exc}") from exc
        finally:
            conn.close()

    def append_audit(
        self,
        conn: sqlite3.Connection,
        tenant: str,
        request_id: str | None,
        version: int | None,
        event: str,
        detail: dict,
    ) -> None:
        conn.execute(
            "INSERT INTO audit_log(tenant, request_id, version, event,"
            " detail_json, created_at) VALUES (?,?,?,?,?,?)",
            (tenant, request_id, version, event, _dumps(detail), time.time()),
        )

    @contextmanager
    def write_transaction(self) -> Iterator[sqlite3.Connection]:
        """通用写事务上下文（失败自动回滚）。"""
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
