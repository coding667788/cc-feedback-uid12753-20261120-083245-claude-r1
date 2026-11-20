"""并发测试：用线程 Event 同步点固定先后顺序，验证写事务串行化与
基准版本乐观并发——后提交者必须重验基准版本并失败，且无中间状态。"""

import threading
import time
import unittest

from solution.barriers import EventHooks
from solution.errors import ERR_BASE_VERSION
from solution.service import PublisherService
from tests._helpers import (
    TENANT,
    initial_digest,
    make_package,
    new_store,
)


class ConcurrencyTest(unittest.TestCase):
    def setUp(self):
        # 短 busy_timeout：B 等锁最多 2 秒，测试无需长等
        self.store, _ = new_store(self, busy_timeout_ms=2000)
        self.results: dict[str, dict] = {}

    def _publish_in_thread(self, request_id: str, package: dict, hooks) -> None:
        service = PublisherService(self.store, hooks)
        self.results[request_id] = service.publish(
            TENANT, request_id, package
        )

    def test_concurrent_publish_first_wins_second_revalidates_and_fails(self):
        # 两个请求都基于 v0、改同一叶路径，但请求 ID 不同
        package_a = make_package(
            0, [{"op": "set", "path": "/app/timeout", "value": 45}],
            ["alice"], initial_digest(),
        )
        package_b = make_package(
            0, [{"op": "set", "path": "/app/timeout", "value": 90}],
            ["alice"], initial_digest(),
        )

        # 同步点固定先后：
        #   A 在“提交前”停住并持有写锁；B 在锁外阻塞；
        #   放行 A 提交后，B 拿到写锁并重验基准版本，因基准失效被拒。
        # B 不设提交前同步点：它在重验阶段即失败，本就不该到达提交点。
        a_reached = threading.Event()
        a_release = threading.Event()
        hooks_a = EventHooks(
            precommit_reached=a_reached, precommit_release=a_release
        )

        thread_a = threading.Thread(
            target=self._publish_in_thread, args=("req-a", package_a, hooks_a)
        )
        thread_b = threading.Thread(
            target=self._publish_in_thread, args=("req-b", package_b, EventHooks())
        )
        thread_a.start()
        self.assertTrue(a_reached.wait(timeout=10), "A 未到达提交前同步点")

        # B 在 A 持锁期间启动：阻塞在写锁上（busy_timeout=2s 内 A 不会释放）
        thread_b.start()
        time.sleep(0.5)
        self.assertTrue(thread_b.is_alive(), "A 持锁期间 B 必须处于等待状态")

        # 放行 A 完成提交并释放写锁，随后 B 才能继续
        a_release.set()
        thread_a.join(timeout=15)
        self.assertFalse(thread_a.is_alive(), "A 应已结束")
        thread_b.join(timeout=15)
        self.assertFalse(thread_b.is_alive(), "B 应已结束")

        receipt_a = self.results["req-a"]
        receipt_b = self.results["req-b"]

        # 恰好一个成功；另一个在事务内重验基准版本失败
        self.assertTrue(receipt_a["ok"])
        self.assertFalse(receipt_b["ok"])
        self.assertEqual(receipt_b["error"]["code"], ERR_BASE_VERSION)

        state = self.service_inspect()
        # 只有 v0、v1 两个快照，指针精确到 v1，从未出现中间版本
        self.assertEqual([s["version"] for s in state["snapshots"]], [0, 1])
        self.assertEqual(state["pointer_version"], 1)
        self.assertEqual(
            state["published"]["config"]["app"]["timeout"], 45
        )

    def test_reader_never_sees_uncommitted_state(self):
        package = make_package(
            0, [{"op": "set", "path": "/app/timeout", "value": 45}],
            ["alice"], initial_digest(),
        )
        reached = threading.Event()
        release = threading.Event()
        hooks = EventHooks(precommit_reached=reached, precommit_release=release)

        writer = threading.Thread(
            target=self._publish_in_thread, args=("req-w", package, hooks)
        )
        writer.start()
        self.assertTrue(reached.wait(timeout=10))

        # 写事务未提交期间，独立读者连接只能看到已提交的 v0
        for _ in range(5):
            seen = self.store.read_published(TENANT)
            self.assertEqual(seen["version"], 0)
            self.assertEqual(seen["config"]["app"]["timeout"], 30)

        release.set()
        writer.join(timeout=15)
        # 提交后读者立即看到 v1
        seen = self.store.read_published(TENANT)
        self.assertEqual(seen["version"], 1)
        self.assertEqual(seen["config"]["app"]["timeout"], 45)

    def service_inspect(self):
        return PublisherService(self.store).inspect(TENANT)


if __name__ == "__main__":
    unittest.main()
