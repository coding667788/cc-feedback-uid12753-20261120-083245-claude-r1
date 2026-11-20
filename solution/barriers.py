"""基于文件的同步点屏障，用于确定性并发与真实终止测试。

协议（屏障目录内三个文件）::

    <name>.reached   子进程到达钩子时创建（“我已到点”）
    <name>.release   父进程创建后，子进程继续执行（放行）
    <name>.crash     父进程创建后，子进程以 os._exit 立即终止（模拟真实 kill）

只依赖文件存在性，跨 Windows 原生进程稳定；等待带超时，避免测试挂死。
真实终止使用 ``os._exit``：不跑 finally、不刷缓冲，等价于被外部杀死。
"""

from __future__ import annotations

import os
import threading
import time
from pathlib import Path

from .errors import ERR_BARRIER_TIMEOUT, PublishError
from .service import Hooks

CRASH_EXIT_CODE = 7


class EventHooks(Hooks):
    """线程内同步点钩子：用 :class:`threading.Event` 固定并发先后顺序。"""

    def __init__(
        self,
        precommit_reached: threading.Event | None = None,
        precommit_release: threading.Event | None = None,
        postcommit_reached: threading.Event | None = None,
        postcommit_release: threading.Event | None = None,
    ):
        self.precommit_reached = precommit_reached
        self.precommit_release = precommit_release
        self.postcommit_reached = postcommit_reached
        self.postcommit_release = postcommit_release

    def after_snapshot_before_commit(self, context: dict) -> None:
        if self.precommit_reached is not None:
            self.precommit_reached.set()
        if self.precommit_release is not None:
            if not self.precommit_release.wait(timeout=30.0):
                raise PublishError(ERR_BARRIER_TIMEOUT, "线程屏障 precommit 超时")

    def after_commit(self, context: dict) -> None:
        if self.postcommit_reached is not None:
            self.postcommit_reached.set()
        if self.postcommit_release is not None:
            if not self.postcommit_release.wait(timeout=30.0):
                raise PublishError(ERR_BARRIER_TIMEOUT, "线程屏障 postcommit 超时")


class FileBarrierHooks(Hooks):
    """带两个崩溃点（提交前/提交后）的文件屏障钩子。"""

    def __init__(
        self,
        barrier_dir: str,
        name: str = "publish",
        timeout_seconds: float = 30.0,
        poll_interval: float = 0.02,
    ):
        self.dir = Path(barrier_dir)
        self.name = name
        self.timeout = timeout_seconds
        self.poll_interval = poll_interval
        self.dir.mkdir(parents=True, exist_ok=True)

    def _reached_file(self, point: str) -> Path:
        return self.dir / f"{self.name}.{point}.reached"

    def _release_file(self, point: str) -> Path:
        return self.dir / f"{self.name}.{point}.release"

    def _crash_file(self, point: str) -> Path:
        return self.dir / f"{self.name}.{point}.crash"

    def _wait_at_barrier(self, point: str) -> None:
        self._reached_file(point).touch(exist_ok=True)
        deadline = time.monotonic() + self.timeout
        while True:
            if self._crash_file(point).exists():
                # 真实终止：跳过所有 Python 清理逻辑
                os._exit(CRASH_EXIT_CODE)
            if self._release_file(point).exists():
                return
            if time.monotonic() > deadline:
                raise PublishError(
                    ERR_BARRIER_TIMEOUT,
                    f"屏障 {self.name}.{point} 等待放行超时（{self.timeout}s）",
                )
            time.sleep(self.poll_interval)

    def after_snapshot_before_commit(self, context: dict) -> None:
        self._wait_at_barrier("precommit")

    def after_commit(self, context: dict) -> None:
        self._wait_at_barrier("postcommit")


# --------------------------------------------------------------- 父进程侧工具
def wait_reached(barrier_dir: str, name: str, point: str, timeout: float = 30.0) -> Path:
    """父进程等待子进程到达某个同步点。"""
    reached = Path(barrier_dir) / f"{name}.{point}.reached"
    deadline = time.monotonic() + timeout
    while not reached.exists():
        if time.monotonic() > deadline:
            raise TimeoutError(f"等待 {reached} 超时")
        time.sleep(0.02)
    return reached


def release(barrier_dir: str, name: str, point: str) -> None:
    (Path(barrier_dir) / f"{name}.{point}.release").touch(exist_ok=True)


def request_crash(barrier_dir: str, name: str, point: str) -> None:
    (Path(barrier_dir) / f"{name}.{point}.crash").touch(exist_ok=True)
