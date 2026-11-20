# 离线配置发布器（Offline Config Publisher）

仅依赖 Python 3.12 标准库（`sqlite3`、`hashlib`、`hmac`、`json`、`threading`、
`subprocess` 等），在本地测试目录离线运行，不访问网络、不使用第三方包或额外算力。

实现一个带**不可变快照**、**模拟验签**、**逐叶路径授权**与**高敏双角色**控制的
配置发布器：变更包绑定目标、基准版本和规范配置摘要，含有序 `set`/`delete`
JSON Pointer 操作；所有发布在单个 SQLite 写事务内重验并原子提交。

---

## 1. 目录结构

```
作答工作区/
├── solution/                 # 被测实现（纯标准库）
│   ├── __init__.py
│   ├── __main__.py           # python -m solution 入口
│   ├── cli.py                # run / worker / inspect 三个子命令
│   ├── errors.py             # 稳定错误码与 PublishError
│   ├── canonical.py          # 规范化 JSON、包摘要、HMAC 模拟验签
│   ├── jsonptr.py            # JSON Pointer、set/delete、叶路径并集
│   ├── schema.py             # 最终 schema 校验（内置最小子集）
│   ├── authz.py              # 作用域覆盖、高敏双角色、签名核验
│   ├── package.py            # 变更包结构校验与有序应用
│   ├── store.py              # SQLite 不可变快照、触发器、幂等、审计
│   ├── service.py            # 事务内重验、发布、幂等、崩溃钩子
│   └── barriers.py           # 文件屏障（真实终止）与线程事件屏障
├── tests/                    # 自动化测试（70 个，独立判定期望）
│   ├── _helpers.py
│   ├── test_01_pointer.py
│   ├── test_02_authz.py
│   ├── test_03_publish.py
│   ├── test_04_idempotency.py
│   ├── test_05_revalidation.py
│   ├── test_06_concurrency.py
│   ├── test_07_process_crash.py
│   ├── test_08_cli_cases.py
│   └── test_09_schema_edges.py
├── tools/
│   └── make_cases.py         # 合成 cases.json（含独立参考实现）
├── cases.json                # 可重放场景（17 个请求 + 手定期望）
├── result.json               # 重放产物（运行后生成）
└── README.md
```

---

## 2. 快速开始（题目指定的两条命令）

在仓库根目录（本文件所在目录）执行：

```bash
# 1) 离线重放场景，产出 result.json（同时在同目录生成 *.sqlite3 数据库）
python -m solution --input cases.json --output result.json

# 2) 运行全部自动化测试
python -m unittest discover -s tests -v
```

可选：重新合成输入（内容确定性，重跑生成等价文件）：

```bash
python tools/make_cases.py
```

查看某个数据库的当前发布状态：

```bash
python -m solution inspect --db result.sqlite3 --tenant t1
```

> 关于 `-I`（隔离模式）：Python 3.12 的 `python -I` 不会把当前目录加入
> `sys.path`，因此 `python -I -m solution` 在仓库根目录会报
> `No module named solution`，这是解释器的既定行为，与本实现无关。
> 题目指定的命令使用普通模式，可正常运行。崩溃测试的子进程也使用普通
> `python -m solution` 并把工作目录固定到仓库根。

---

## 3. 输入结构（cases.json）

顶层对象：

| 字段 | 含义 |
| --- | --- |
| `scenario_name` / `description` | 场景标识与说明 |
| `bootstrap` | 租户、目标、schema、高敏前缀、初始配置、签名者 |
| `requests` | 有序请求序列，每项含一个变更包和手定期望 `expect` |

### 3.1 bootstrap

```json
{
  "tenant": "t1",
  "target": "app-config",
  "schema": { "type": "object", "...": "..." },
  "sensitive_prefixes": ["/security"],
  "initial_config": { "app": {"...": "..."}, "security": {"...": "..."}, "features": {"...": "..."} },
  "initial_config_digest": "<sha256 hex，由规范化哈希独立计算>",
  "signers": [
    {"identity": "alice", "role": "publisher", "scopes": ["/app", "/features"],
     "secret": "secret-alice", "active": true}
  ]
}
```

* `role` 仅允许 `publisher`（发布）与 `reviewer`（复核）。
* `scopes` 是 JSON Pointer 前缀集合，覆盖“自身及其全部子树”；`""` 表示根。
* `sensitive_prefixes` 落在其下的每个叶路径都要求两个独立角色。

### 3.2 变更包 package

```json
{
  "target": "app-config",
  "base_version": 3,
  "config_digest": "<基准快照的规范配置摘要>",
  "operations": [
    {"op": "set", "path": "/app/timeout", "value": 45},
    {"op": "delete", "path": "/security/tokens"}
  ],
  "signatures": [
    {"identity": "alice", "signature": "<hmac-sha256 hex>"}
  ]
}
```

* `target` 必须与租户绑定目标一致；`base_version` 必须等于当前发布指针版本；
  `config_digest` 必须等于基准快照摘要。
* `operations` 非空、按数组顺序应用；`set` 必须带 `value`，`path` 为 RFC 6901。
* 包摘要 `package_digest = sha256(canonical(target, base_version,
  config_digest, operations))`，**不含** signatures 字段（避免自引用）。
* 每个签名 = `HMAC_SHA256(signer.secret, package_digest)`，全部绑定同一份
  完整包摘要；改包内任意字节都会使验签失败。

### 3.3 请求信封

```json
{"tenant": "t1", "request_id": "r01-app-timeout", "package": { "...": "..." },
 "expect": {"ok": true, "status": "COMMITTED", "version": 1}}
```

`expect` 是**手工确定**的独立判定，测试据此断言，绝不从被测运行结果反推。

---

## 4. 关键安全语义

### 4.1 叶路径与授权

* 标量、`null` 与**数组整体**是叶；非空对象向下递归；空对象/空数组是终端叶
  （自身即一条叶路径），保证删除/清空对象时仍有路径需要授权。
* 每项操作最终受影响的叶路径都必须被至少一个当前有效签名者的作用域覆盖。
* **替换或删除整个对象**：受影响集合取“原子树叶路径 ∪ 新子树叶路径”并集。
* 向空对象增/删键导致容器在“叶 ↔ 非叶”间切换时，该终端祖先路径也计入并集。
* `set` 允许在已存在的对象父节点下创建具体键；不允许自动创建缺失的中间嵌套路径。

### 4.2 数组规则

* 数组整体视作一个叶，**禁止数组下标变化**：`/arr/0` 形式的 set/delete 一律拒绝
  （`ARRAY_INDEX_FORBIDDEN`）。
* 允许把整个数组作为一个值替换（`/arr`），授权只针对 `/arr` 这一条叶路径。

### 4.3 高敏双角色

* 落在 `sensitive_prefixes` 子树内的叶路径，要求一名 `publisher` 与一名
  `reviewer`，且二者作用域都覆盖该叶路径、身份相互独立。
* 一人发布、一人复核；两个签名都绑定完整包摘要。普通叶路径至少一名有效签名者。

### 4.4 事务内重验（不可复用预检结论）

发布先 `BEGIN IMMEDIATE` 取得写锁，再在同一事务内重新验证：

1. 基准版本 == 当前发布指针版本（`BASE_VERSION_MISMATCH`）；
2. 包绑定的规范配置摘要 == 基准快照摘要（`CONFIG_HASH_MISMATCH`）；
3. 签名者**当前**启用状态与作用域（`SIGNER_INACTIVE` / `SCOPE_DENIED`）；
4. 全部签名仍匹配完整包摘要（`SIGNATURE_INVALID`）；
5. 最终配置树通过 schema（`SCHEMA_VIOLATION`）；
6. request_id 与参数（包摘要）的幂等约束。

因此“预检通过后撤权”会在发布时被拒；并发的后到者拿锁后看到的是最新已提交状态，
基准失效即被拒，不会产生重复版本。

### 4.5 不可变快照与恢复旧内容

* `config_snapshots` 上有触发器禁止 `UPDATE`/`DELETE`，只追加；版本号单调递增。
* 发布指针、新快照、请求回执、审计在**同一写事务**提交，读者要么看到旧版本、
  要么看到新版本，不存在中间状态。
* 把内容改回旧值也必须基于当前版本重新造包、重新签名、重新授权，产生**新版本**；
  旧签名与旧前置条件（旧 base_version / 旧 digest）不可复用。同摘要可对应多个代际。

### 4.6 请求 ID 幂等（租户内唯一）

* 同 `(tenant, request_id)` 同参数（包摘要相同）：返回第一次持久化的结果，
  `replayed=true`，不产生新版本。
* 同 ID 异参：拒绝（`REQUEST_PARAM_MISMATCH`），不修改业务状态、不占用该 ID。
* 业务失败回执单独持久化（`status=FAILED, version=null`），与业务状态
  （快照/指针保持不变）明确区分；同 ID 重放失败请求返回首次失败回执。

---

## 5. 错误码表

| 错误码 | 触发条件 |
| --- | --- |
| `MALFORMED_PACKAGE` | 变更包缺字段、类型错误、operations 为空等 |
| `UNKNOWN_OPERATION` | 操作不是 set/delete |
| `INVALID_POINTER` | 指针语法非法、非法转义、删除根节点 |
| `ARRAY_INDEX_FORBIDDEN` | 对数组下标赋值/删除（数组整体是叶） |
| `PARENT_NOT_OBJECT` | 赋值/删除目标的父节点不是对象 |
| `POINTER_NOT_FOUND` | 中间路径缺失或删除不存在的键 |
| `SIGNATURE_INVALID` | 签名与完整包摘要不匹配（含包被篡改） |
| `UNKNOWN_SIGNER` | 签名者不在注册表 |
| `SIGNER_INACTIVE` | 签名者已停用/被撤权 |
| `SCOPE_DENIED` | 某受影响叶路径未被任何签名者作用域覆盖 |
| `HIGH_SENSITIVE_DUAL_CONTROL_REQUIRED` | 高敏叶路径缺 publisher/reviewer 双角色或作用域不足 |
| `ROLE_INVALID` | 缺 publisher 或出现非法角色 |
| `SCHEMA_VIOLATION` | 最终配置树不通过 schema |
| `BASE_VERSION_MISMATCH` | 基准版本与当前发布版本不一致 |
| `TARGET_MISMATCH` | 包目标与租户绑定目标不同 |
| `CONFIG_HASH_MISMATCH` | 包绑定摘要与基准快照摘要不一致 |
| `REQUEST_PARAM_MISMATCH` | 同 request_id 携带不同参数 |
| `UNKNOWN_TENANT` | 租户不存在 |
| `BARRIER_TIMEOUT` | 同步点等待超时 |
| `STORAGE_ERROR` | SQLite 初始化/写入等基础设施错误 |

回执中 `status` 取值：`COMMITTED`（成功）、`FAILED`（业务校验失败，已持久化回执）、
`REJECTED`（请求级拒绝，如幂等异参，不占用 request_id）。

---

## 6. 边界示例

| 场景 | 输入要点 | 结果 |
| --- | --- | --- |
| 数组下标赋值 | `set /app/tags/0 = "blue"` | `ARRAY_INDEX_FORBIDDEN` |
| 数组整体替换 | `set /app/tags = ["a","b"]` | 成功，受影响叶仅 `/app/tags` |
| 创建具体键 | 父对象存在，`set /features/beta = true` | 成功，新叶 `/features/beta` |
| 缺失中间路径 | `set /features/sub/flag` 而 `/features/sub` 不存在 | `POINTER_NOT_FOUND` |
| 替换整个对象 | `set /security/tokens = {primary,secondary}` | 并集含 primary+secondary，需双角色 |
| 删除整个对象 | `delete /security/tokens` | 原子树叶 `/security/tokens/primary` 需双角色 |
| 空对象终端 | `set /features = {}` 后再 `set /features/beta` | 两次都把 `/features` 终端叶计入并集 |
| 高敏单角色 | 仅 publisher 改 `/security/mode` | `HIGH_SENSITIVE_DUAL_CONTROL_REQUIRED` |
| 篡改签名 | 把 signature 改成全 0 | `SIGNATURE_INVALID` |
| 预检后撤权 | precheck 通过后停用签名者再 publish | `SIGNER_INACTIVE`，指针不动 |
| 同 ID 同参重放 | 重复提交完全相同的包 | 返回首次结果，`replayed=true` |
| 同 ID 异参 | 复用 request_id 但改 value | `REQUEST_PARAM_MISMATCH` |
| 恢复旧值 | 基于当前版本改回旧内容 | 产生新版本，旧签名不可复用 |
| 根替换 | `set "" = <新整树>` | 全部叶路径并集都需授权，作用域不足即拒 |

---

## 7. 并发、崩溃与可恢复性

* **确定性并发**（`test_06_concurrency.py`）：用 `threading.Event` 同步点固定先后——
  线程 A 在“提交前”停住并持有写锁，线程 B 在锁外等待；放行 A 后 B 拿锁并重验，
  因基准版本失效被拒。读者线程在 A 未提交期间反复读取，只能看到已提交的旧版本。
* **真实进程终止**（`test_07_process_crash.py`）：测试用 `subprocess.Popen` 启动
  **本测试自建的** worker 子进程（只 terminate/等待这些子进程，绝不按名杀系统中
  其他 Python），通过文件屏障在两处触发 `os._exit(7)`：
  * **崩溃点 A（快照已写入、事务未提交）**：重启后事务回滚，指针停在 v0、无 v1
    快照、无请求行、无回执文件；读者从未见到中间状态。
  * **崩溃点 B（提交已完成）**：重启后 v1 已持久化，快照链 `[0,1]`，幂等与审计
    记录随事务落盘。
  * A 点崩溃后用同一 request_id 重试可正常成功，证明未提交中断以重启后的数据库
    状态为准、不残留半成品。

---

## 8. 测试的独立性（期望值来源）

* 签名与摘要只复用 `solution.canonical` 的哈希/HMAC **原语**（测试夹具能力），
  不经过被测的发布/授权逻辑。
* `tools/make_cases.py` 与 `tests/_helpers.py` 各自包含一个**独立参考变更器**
  `ref_apply`（普通字典 set/delete），逐版本计算期望配置与期望摘要。
* 每个请求的期望错误码、版本号、受影响叶路径都手工写在 `expect` 中，
  测试逐条断言；没有任何期望值从 solution 的运行回执反推。
* 崩溃/并发测试断言的是重启后的数据库状态与读者可见版本，而非进程内变量。

---

## 9. 实测结果

环境：Windows 11 Pro 10.0.26200，原生 Python 3.12.8，SQLite 3.45.3，仅标准库/CPU。

```
$ python -m solution --input cases.json --output result.json
已重放 17 个请求 -> result.json

$ python -m unittest discover -s tests -v
...
Ran 70 tests in 4.0s

OK
```

17 个场景请求的实测结果（与 cases.json 内 `expect` 完全一致）：

| request_id | ok | status/错误码 | 版本 |
| --- | --- | --- | --- |
| r01-app-timeout | ✓ | COMMITTED | 1 |
| r02-bad-signature | ✗ | SIGNATURE_INVALID | — |
| r03-sensitive-single | ✗ | HIGH_SENSITIVE_DUAL_CONTROL_REQUIRED | — |
| r04-sensitive-dual | ✓ | COMMITTED | 2 |
| r05-array-index | ✗ | ARRAY_INDEX_FORBIDDEN | — |
| r06-array-replace | ✓ | COMMITTED | 3 |
| r06-array-replace（重放） | ✓ | COMMITTED（replayed） | 3 |
| r06-array-replace（异参） | ✗ | REQUEST_PARAM_MISMATCH | — |
| r09-stale-base | ✗ | BASE_VERSION_MISMATCH | — |
| r10-create-key | ✓ | COMMITTED | 4 |
| r11-create-deep-missing | ✗ | POINTER_NOT_FOUND | — |
| r12-schema-enum | ✗ | SCHEMA_VIOLATION | — |
| r13-delete-object | ✓ | COMMITTED | 5 |
| r14-replace-sensitive-parent | ✓ | COMMITTED | 6 |
| r15-scope-denied | ✗ | SCOPE_DENIED | — |
| r16-unknown-signer | ✗ | UNKNOWN_SIGNER | — |
| r17-target-mismatch | ✗ | TARGET_MISMATCH | — |

最终发布指针版本 `6`，快照链 `[0,1,2,3,4,5,6]`；失败请求不产生任何快照。
测试以 `-W error::ResourceWarning` 运行同样通过，无句柄泄漏。
