"""命令行入口。

* ``python -m solution --input cases.json --output result.json``
  按场景文件离线重放全部请求（等价于 ``run`` 子命令）；
* ``python -m solution worker --db PATH --request req.json``
  带文件屏障的单次发布工作进程，供“真实终止”测试驱动；
* ``python -m solution inspect --db PATH --tenant t1``
  读者视角查看当前发布版本、快照链与请求/审计记录。
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from .barriers import FileBarrierHooks
from .errors import PublishError
from .service import PublisherService
from .store import Store


def _load_json(path: str) -> Any:
    # 显式 utf-8，Windows 原生默认编码不影响离线数据
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _dump_json(path: str, value: Any) -> None:
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(value, fh, ensure_ascii=False, indent=2, sort_keys=True)
        fh.write("\n")


def _build_store(db_path: str, scenario: dict) -> tuple[Store, PublisherService]:
    store = Store(db_path)
    store.init_schema()
    bootstrap = scenario["bootstrap"]
    store.bootstrap_tenant(
        tenant=bootstrap["tenant"],
        target=bootstrap["target"],
        schema=bootstrap["schema"],
        sensitive_prefixes=bootstrap["sensitive_prefixes"],
        initial_config=bootstrap["initial_config"],
        signers=bootstrap["signers"],
    )
    return store, PublisherService(store)


def cmd_run(args: argparse.Namespace) -> int:
    scenario = _load_json(args.input)
    db_path = args.db
    if db_path is None:
        # 默认与输出文件同目录、同名 .sqlite3，保证离线可重放
        db_path = str(Path(args.output).with_suffix(".sqlite3"))
    # 全新数据库，保证重放确定性
    for suffix in ("", "-wal", "-shm"):
        Path(db_path + suffix).unlink(missing_ok=True)

    _store, service = _build_store(db_path, scenario)
    results: list[dict] = []
    for request in scenario["requests"]:
        receipt = service.publish(
            request["tenant"], request["request_id"], request["package"]
        )
        results.append(
            {
                "request_id": request["request_id"],
                "ok": receipt["ok"],
                "replayed": receipt.get("replayed", False),
                "status": receipt.get("status"),
                "version": receipt.get("version"),
                "base_version": receipt.get("base_version"),
                "error": receipt.get("error"),
                "affected_leaves": receipt.get("affected_leaves"),
                "signer_identities": receipt.get("signer_identities"),
                "package_digest": receipt.get("package_digest"),
                "new_config_digest": receipt.get("new_config_digest"),
            }
        )
    final_state = service.inspect(scenario["bootstrap"]["tenant"])
    output = {
        "scenario": scenario.get("scenario_name", "offline-config-publisher"),
        "db_path": os.path.abspath(db_path),
        "results": results,
        "final_pointer_version": final_state["pointer_version"],
        "final_config": final_state["published"]["config"],
        "final_config_digest": final_state["published"]["config_digest"],
        "snapshot_versions": [item["version"] for item in final_state["snapshots"]],
    }
    _dump_json(args.output, output)
    print(f"已重放 {len(results)} 个请求 -> {args.output}")
    return 0


def cmd_worker(args: argparse.Namespace) -> int:
    """带屏障的单次发布进程；请求 JSON 内含 barrier_dir/name 与 db 路径。"""
    request = _load_json(args.request)
    store = Store(request["db"])
    # 工作进程要求库与租户已由父进程初始化
    hooks = FileBarrierHooks(
        request["barrier_dir"],
        name=request.get("barrier_name", "publish"),
        timeout_seconds=request.get("barrier_timeout", 30.0),
    )
    service = PublisherService(store, hooks)
    receipt = service.publish(
        request["tenant"], request["request_id"], request["package"]
    )
    _dump_json(request["receipt_path"], receipt)
    print(f"worker 完成: {receipt.get('status')} version={receipt.get('version')}")
    return 0


def cmd_inspect(args: argparse.Namespace) -> int:
    store = Store(args.db)
    service = PublisherService(store)
    try:
        state = service.inspect(args.tenant)
    except PublishError as exc:
        print(json.dumps({"ok": False, "error": exc.to_dict()}, ensure_ascii=False))
        return 2
    _dump_json(args.output, state) if args.output else print(
        json.dumps(state, ensure_ascii=False, indent=2, sort_keys=True)
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m solution",
        description="离线配置发布器：不可变快照 + 模拟验签 + 高敏双角色",
    )
    parser.add_argument("--input", help="场景输入 cases.json（默认 run 模式）")
    parser.add_argument("--output", help="结果输出 result.json")
    parser.add_argument("--db", help="SQLite 数据库路径（默认随 --output 推导）")
    sub = parser.add_subparsers(dest="command")

    p_run = sub.add_parser("run", help="重放场景文件（也可用顶层 --input/--output）")
    p_run.add_argument("--input", required=True)
    p_run.add_argument("--output", required=True)
    p_run.add_argument("--db")
    p_run.set_defaults(func=cmd_run)

    p_worker = sub.add_parser("worker", help="屏障工作进程（测试驱动）")
    p_worker.add_argument("--request", required=True)
    p_worker.set_defaults(func=cmd_worker)

    p_inspect = sub.add_parser("inspect", help="查看租户发布状态")
    p_inspect.add_argument("--db", required=True)
    p_inspect.add_argument("--tenant", required=True)
    p_inspect.add_argument("--output")
    p_inspect.set_defaults(func=cmd_inspect)

    parser.set_defaults(func=cmd_run)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    # 兼容无显式子命令、直接给 --input/--output 的题目要求
    if args.command is None:
        if not args.input or not args.output:
            parser.error("需要 --input cases.json --output result.json（或使用子命令）")
    try:
        return args.func(args)
    except PublishError as exc:
        print(
            json.dumps({"ok": False, "error": exc.to_dict()}, ensure_ascii=False),
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
