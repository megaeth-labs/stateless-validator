# coverage-replayer：mega-evm 主网覆盖率最小块集合的持续维护服务（设计稿）

- **日期**：2026-07-08
- **状态**：Draft，供讨论
- **基线**：`main` @ `01613af`（mega-evm `v1.6.1`，salt `v1.0.5`，toolchain `nightly-2026-02-03`）
- **前期调研**：`liquan/mega_evm_coverage` 分支（spike，仅作参考，不合并）

## 1. 背景与目标

前期 spike 在 `liquan/mega_evm_coverage` 分支上验证了做法的可行性：给 stateless-validator 全量插桩，逐块生成 profraw，用 llvm 工具导出行覆盖，再用贪心集合覆盖挑出"覆盖率最大、块数最少"的主网块集合（当时 ~2.4k 行 universe，最终 5–9 个块）。`test_data/mainnet` 里现有的那批块就是这么来的。

但 spike 的形态无法持续运营：

1. 复用了完整 validator（witness 验证 + SALT 状态根更新都在跑，且都被插桩拖慢），而覆盖率只关心 mega-evm 的执行路径；
2. 每个块要冷启动一个子进程（重新解析 genesis、序列化全部输入走临时文件）；
3. 内联分析器在 `Mutex` 里对每个块各跑一次 `llvm-profdata` + `llvm-cov`（秒级、串行），实际吞吐接近单线程；
4. 结果是一次性的：mega-evm 升级后需要人工重跑整个流程。

**目标**：一个基于 main 的常驻服务 `coverage-replayer`，持续跟随主网执行新块、维护 branch 粒度的覆盖率最小块集合，并在集合发生实质变化时自动向本仓库提 PR 更新 `test_data/mainnet`。

**非目标**：

- 不校验区块正确性（正式 stateless-validator 服务已在保证每个块和 witness 的正确性），只保留免费的 sanity check；
- 不做多机分片（单机多核吞吐已远超需求，设计上留出按块区间分片的余地即可）；
- 不做 MC/DC 粒度。

## 2. 总体架构

单一二进制、按 flag 分角色（沿用现有 self-spawn 模式），单机部署：

```
                    ┌────────────────────────────────────────────────────┐
 MegaETH RPC        │ coverage-replayer（dispatcher 进程，不采集覆盖率）      │
 mainnet.megaeth.com│                                                    │
   │  get_block     │  fetcher 任务（lag 跟随链头）                         │
   ├───────────────▶│    get_block + get_witness → 解码 → SpoolEntry 落盘  │
   │  get_witness   │                                                    │
   │  get_codes     │  scheduler：spool → 派发给 worker 池                  │
   └───────────────▶│                                                    │
                    │  judge：收 bitmap → pattern 判定 → 删除 / 晋升归档     │
                    │  store：redb（pattern 位图库、watermark、索引）        │
                    └───────┬────────────────────────────────────────────┘
                            │ JSONL over stdin/stdout
              ┌─────────────┴─────────────┐
              │ worker 子进程 × N（常驻，同一二进制 --internal-worker）        │
              │  循环：reset counters → 读 SpoolEntry → replay_block       │
              │       → capture profraw → 提取非零 counter 位图 → 返回      │
              └───────────────────────────┘

 定时任务（同一二进制的子命令，cron 触发）：
   set-cover  ：位图库 → 贪心 → 候选集合 manifest
   pr-bot     ：候选集合 vs main 上的 manifest → 组装 test_data → 本地跑测试 → 提 PR
   report     ：对入选块跑 llvm-cov，出 HTML/明细（唯一用到 llvm 工具链的地方）
```

关键原则：

- **覆盖率隔离靠进程**：counter 是进程全局的，采集只发生在 worker 子进程里；dispatcher 里跑 fetcher/judge 不会污染覆盖率（这是 spike 中 `coverage_worker.rs` 已验证的模式）。
- **llvm 工具链不在热路径上**：集合覆盖只需要"每块的非零 counter 位图"，不需要源码行号。`llvm-cov` 只在出人类可读报告时使用。
- **worker 常驻**：标准 profiler runtime（rustc 随 `-C instrument-coverage` 自动链接）的 `__llvm_profile_reset_counters()` / `__llvm_profile_write_file()` 经 FFI 直调，允许一个进程串行处理任意多个块，进程冷启动、genesis 解析、输入序列化的开销全部消失。

## 3. 对 main 代码的复用与新增

### 复用（不改或几乎不改）

| 模块                                                       | 用途                                                                                               |
| ---------------------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| `stateless-common::rpc_client::RpcClient`                  | `get_block` / `get_witness`（一次返回 `(SaltWitness, MptWitness)`，多 provider 容错）/ `get_codes` |
| `stateless-core::light_witness::LightWitness`              | worker 的执行态输入：`kvs + levels`，反序列化 ~10–20ms；SaltWitness 完整解码经 salt PR #137（v1.0.5 已含，`parallel` feature 经 `stateless-core/std → salt/default` 默认开启）并行化后，6.3 MiB / 65k commitments 实测 ~119ms（14 核，见 §11）——`light_witness.rs` 里 "~240ms" 的注释是 #137 之前的旧数据 |
| `stateless-core::evm_database::WitnessDatabase`            | 基于 witness 的 `DatabaseRef`（debug-trace-server 已在用 LightWitness 驱动它）                     |
| `stateless-core::executor::{create_evm_env, replay_block}` | 纯执行路径，跳过 witness 验证和 SALT 状态根更新                                                    |
| `stateless-core::pipeline`（可选）                         | fetch 窗口/背压/断点逻辑；见 §12 开放问题 1                                                        |
| `stateless-test-utils::TestFixtures`                       | PR 载荷的格式对齐基准（`WitnessFileContent` envelope、`contracts.txt` 行格式等）                   |
| `stateless-common` metrics/logging                         | Prometheus 指标、日志                                                                              |

### 新增

- `bin/coverage-replayer`（新 workspace 成员）：dispatcher / worker / set-cover / pr-bot / report 全部在这一个 crate 里；
- **零新增外部依赖**：覆盖率采集直接 FFI 声明标准 profiler runtime 的 `__llvm_profile_reset_counters` / `__llvm_profile_set_filename` / `__llvm_profile_write_file` 三个符号（E1 已验证）。FFI 调用点用 `coverage` cargo feature 门控，未插桩的常规构建不引用这些符号；
- **`bin/stateless-validator` 与各 crates 源码零改动**。插桩发生在构建层（RUSTFLAGS），只用于这个 bin 的专用构建，正式 validator 的构建产物完全不受影响。

## 4. 数据流与生命周期

### 4.1 fetcher

- 跟随 `latest_block_number - LAG`（`LAG` 可配，默认 ~32 块），刻意滞后以回避 reorg 处理；backfill 模式则按给定区间扫。
- 每块调用 `get_block(full_txs)` + `get_witness` → 得到 `Block`、`SaltWitness`、`MptWitness`。
- witness 获取走 `RpcClient::get_witness_light`（E5 已实现）：`LightWitnessFromSalt` 直接从 wire 字节解出 kvs+levels，**零 EC 运算**（大 witness bincode 部分 ~1.4ms 单线程，对比 full 解码 ~110ms wall / ~1 core·s）。**完整 witness 全程不落盘**：唯一需要它的时刻是 PR bot 组装 test_data 载荷，届时对入选的少数几个块从 RPC 现拉（E4：全历史可用）。
- 落盘一个 SpoolEntry（目录 `spool/`，每块一个文件，bincode+zstd）：

```rust
struct SpoolEntry {
    block_json: Vec<u8>,        // RPC 返回的 Block JSON 原文（晋升时直接写 test_data）
    parent_hash: B256,
    light_witness: LightWitness, // worker 执行用（快速加载）
    code_hashes: Vec<B256>,      // 从 witness 提取的本块所需 code hash
}
```

  说明：spool 只存执行所需的 light 数据。曾考虑过并存 raw witness payload 供晋升归档，已否决——E4 保证 RPC 可拉全历史，raw 随存随删纯属浪费，需要完整 witness 的唯一场景（PR 载荷）按需现拉即可。

- 字节码：维护 `codes/` 内容寻址缓存（code hash → bytecode，**常驻不删**，总量有限、复用率极高）；fetcher 对 spool 条目中缺失的 hash 调 `get_codes` 补齐。

### 4.2 worker（常驻子进程 × N）

协议：JSONL over stdin/stdout，一问一答。

```jsonc
// dispatcher → worker
{"block": 14920039, "spool": "spool/14920039.bin"}
// worker → dispatcher
{"block": 14920039, "ok": true, "gas_used": 123456, "gas_expected": 123456,
 "bitmap": "<roaring base64>", "profraw": "tmp/14920039.profraw", "elapsed_ms": 18}
```

worker 内每块的循环：

1. `__llvm_profile_reset_counters()`；
2. 加载 SpoolEntry → `LightWitness` → `WitnessDatabase` + codes 缓存 → `create_evm_env` → `replay_block`（**不做** witness 验证 / 状态根更新 / withdrawals 校验）；
3. **sanity check**：执行产出的累计 `gas_used` 与区块头对比。不一致 = chain spec/硬分叉配置漂移（Rex4 教训），该块标记 `divergent`、连续多块不一致则告警并暂停入库——防止静默污染整个位图库；
4. `__llvm_profile_set_filename(块专属路径)` + `__llvm_profile_write_file()` 写出本块 profraw → 提取**非零 counter 位图**（见 §5）→ 返回。

失败处理：worker panic/OOM → dispatcher 重启该 worker、块重试一次；仍失败 → 块进隔离名单并告警（panic 路径本身往往是有价值的覆盖率信号，值得人工看）。

### 4.3 judge：pattern 判定与保留策略

维护 `patterns` 表：`pattern_hash（位图内容哈希） → { bitmap, first_block, last_block, hit_count, representative_block }`。

- 块的位图 **已存在**（绝大多数块）→ 更新计数 → **删除** spool 条目和 profraw。这就是"跑完一个删一个"，但判定依据是 pattern 是否新，而不是"是否带来新覆盖"；
- 位图是 **新 pattern** → 该块成为此 pattern 的代表块（representative）→ 晋升时**只保留一个 ~100KB 的稀疏 profdata**（`llvm-profdata merge -sparse` 丢掉全部零计数函数及其名字表，再 zstd；raw profraw ~4.7MB 且名字表不可压缩，实测 ~45x 缩减；转换在 judge 关键路径之外异步执行）。spool 条目照删——代表块的 block/witness 数据在重扫或 PR 组装需要时按块号从 RPC 现拉（E4）。

为什么按 pattern 而不是"新覆盖"保留：最小集合覆盖可能选中一个**不带来任何新覆盖但单块覆盖面很大**的块（例：先见 {a,b} 和 {c}，后来 {a,b,c} 出现——最优解恰恰是只选 {a,b,c}）。只保留"带来新行的块"会让贪心失去这类候选。distinct pattern 的数量有界（主网块高度重复，预计数千级），归档成本可控。

可选剪枝（在 set-cover 任务里做，不在热路径）：pattern P ⊆ Q 时 P 永远不会优于 Q（任何含 P 的覆盖把 P 换成 Q 仍是覆盖且不变大），可安全删除 P 及其归档，保留候选池为反链（antichain）。

### 4.4 版本升级重扫（E4 已确认，无需 window 归档）

mega-evm 升级（binary_id 变化）后 counter 编号全部失效，需要重扫。**E4 结论：主网 RPC 可获取 block 1 到最新块的全部 witness**，因此原设计中的滚动 window 归档整体取消——重扫直接用 backfill 模式从 RPC 拉取。推荐顺序：先按 store 里记录的历史代表块号从 RPC 重拉回放 + 近期区间，快速建立新命名空间的基线，再按需扩大扫描范围。

## 5. 覆盖粒度与位图提取

- 构建带 `-Z coverage-options=branch`（仓库 toolchain 本就是 nightly，无额外门槛），branch 的 true/false 计数在 profraw 里就是普通 counter；
- **位图 = 非零 counter 集合，天然就是 branch 粒度**，集合覆盖直接在 branch 粒度上进行，无需任何源码映射;
- 位图提取 v1：worker 对自己的 profraw 跑 `llvm-profdata merge --text`（毫秒级小进程，完全并行），解析出各函数的 counter 值，`(symbol, counter_idx)` 非零集合经全局稳定索引（`counter_index` 表：`(symbol, idx) → dense_id`，按 binary_id 命名空间持久化）映射成 roaring bitmap。实验 E2 已验证此路径（见 §11）；
- v2 优化（可选）：进程内直接解析 profraw counters 段（`llvm_profparser` crate 或自写、按 rustc 版本锁定），省掉每块一次小进程；
- **过滤**：只保留 mega-evm（及明确关心的 crate）符号的 counter，dispatcher 侧按 symbol 前缀过滤一次、缓存进 `counter_index`，位图规模保持在万级 bit；
- `llvm-cov` 仅在 `report` 子命令中使用：把入选块的归档 profraw merge 后 `llvm-cov show/export`，出行/branch 明细与 HTML，供 PR 描述和人工审阅。

## 6. 存储布局

```
data-dir/
├── spool/        # 待处理 SpoolEntry；判定后即删（分钟级存量）
├── archive/      # profiles/：每 pattern 一个稀疏 profdata（zstd，~100KB），唯一消费者是 report
├── codes/        # code hash → bytecode 内容寻址缓存（常驻）
├── tmp/          # worker 的 profraw / symbols 边车（判定后即删）
├── manifest.json # set-cover 输出
└── store.redb    # 表：meta(binary_id)、counters(id64 → dense/symbol)
                  #     patterns(pattern_key → bitmap/representative/计数)
                  #     blocks(块号 → 状态/hash/pattern_key，兼作断点与隔离名单)
```

所有覆盖率数据按 **binary_id**（replayer 二进制内容哈希，启动时自算自校验）命名空间隔离；binary_id 变化 → 自动进入 bootstrap 重扫流程（§4.4），旧命名空间保留一段时间供对比后清理。M1 取整个可执行文件的哈希（严格但保守：replayer 自身改码也会触发重扫）；M2 可改为只对 mega-evm 相关符号/covmap 取哈希——counter id 本身是 `(symbol, func_hash, idx)` 内容寻址的，只要 mega-evm 编译产物不变就天然稳定。

### 存储回收

原则：**bitmap 是唯一不可再生的资产**（重算需重放执行），永久保留、体积微小；其余一切都可再生（block/witness 可从 RPC 全历史拉取，profdata 可重放再生），按下表回收。完整 witness 与代表块数据任何时候都不落盘（实测教训：raw profraw 即使 zstd 也只有 2.3x——二进制的函数名字表不可压缩；`-sparse` 转换后 ~45x，每 pattern ~106KB）。

| 层 | 机制 | 状态 |
| --- | --- | --- |
| spool / tmp | 判定后即删（dup pattern 删全部；晋升块移入 archive 后原地删除） | M1 已实现 |
| 隔离区（Error/Divergent 的 spool 残留） | TTL：只保留最近 N 个（默认 100）供 debug | M2 |
| archive/profiles | ① antichain 剪枝：set-cover 发现 pattern P ⊆ Q 时连同其 profdata 删除；② 体积已实测极小（~106KB/pattern，391 个 ≈ 41MB），配额兜底降级为可选 | M2 |
| 旧 binary_id 命名空间 | 版本升级重扫收敛后整体删除（保留 K 天对比期） | M2 |
| codes/ | 刻意不回收：内容寻址、总量有限、复用率极高 | 维持 |

## 7. 集合覆盖与稳定性

- universe = 当前命名空间内所有 pattern 位图的并集；
- 贪心：每轮选"新增覆盖最多"的候选块，平局裁决顺序：**① 已在当前 manifest 中的块（压制抖动）→ ② 覆盖增量大 → ③ 块号更新**。spike 中的 reverse-greedy 刻意偏好新块，会最大化 churn，弃用；
- 收尾做一遍冗余消除（移除被其余入选块并集完全覆盖的块）；
- **父块约束**：`TestFixtures::paired_blocks` 要求每个 witness 块的父块 JSON 同时存在（`test_data/mainnet/blocks` 现状即成对），晋升归档与 PR 载荷都要连带父块；
- 触发变更的条件（满足其一才进入 PR 流程）：
  1. universe 增长且当前 manifest 集合无法覆盖新增部分（出现了新 pattern 且贪心确认需要换血）；
  2. 集合可以严格变小；
- manifest 作为唯一事实来源，随 PR 一起落在 `test_data/mainnet/coverage_manifest.json`：

```jsonc
{
  "mega_evm_rev": "v1.6.1",
  "binary_id": "sha256:…",
  "generated_at": "2026-07-08T00:00:00Z",
  "universe_counters": 41230,
  "covered_by_selection": 41230,
  "blocks": [
    {"number": 10001452, "hash": "0xb1e5…", "gain": 38112},
    {"number": 14920039, "hash": "0xd64c…", "gain": 2101}
  ]
}
```

## 8. PR bot

状态机（cron 驱动，幂等）：

```
Idle ──贪心结果 ≠ origin/main manifest，且连续 K 次（默认 3 天）稳定──▶ CandidateReady
CandidateReady ──组装载荷 + 本地 `cargo test -p stateless-validator` 通过──▶ PayloadReady
PayloadReady ──推分支 bot/coverage-min-set（force-push 复用）+ 开/更新 PR──▶ PROpen
PROpen ──merge/close 后──▶ Idle    （同一时刻至多一个 open PR）
```

- **载荷**（严格对齐 `TestFixtures` 的读取格式）：
  - `blocks/<n>.<hash>.json`：归档的 RPC Block JSON 原文（含父块）；
  - `stateless/witness/<n>.<hash>.salt` / `.mpt`：**组装时对入选块从 RPC 现拉完整 witness**（`get_witness`，E4 全历史可用；本地不存 raw），再按目标格式落盘——当前为 bincode-legacy `WitnessFileContent` envelope，E6 落地后直接写 `.zst`（`encode_witness_payload` 产物）；
  - `contracts.txt`：按新入选块所需 code hash 追加 `[hash, bytecode]` 行；
  - `coverage_manifest.json`：见 §7；
  - 被移出集合的块的对应文件删除（保持 test_data 最小——这本来就是项目目的）。
- **PR 描述**：覆盖率 before/after、增删块列表及各自贡献（来自 `report` 子命令的 branch 明细）、mega_evm_rev / binary_id。
- **护栏**：
  - 开 PR 前校验"扫描所用 mega-evm rev == origin/main 当前 rev"，不一致则先触发重建+重扫，绝不用旧版本数据提 PR；
  - 频控：默认每周至多一个 PR；例外：universe 出现当前 test_data 覆盖不了的新 pattern 时立即提（这说明主网出现了测试没覆盖的新行为，最有价值的时刻）；
  - 覆盖率相比现有 manifest 下降 → 拒绝提 PR 并告警（数据有问题）。
- **凭证**：机器账号 fine-grained PAT（仅本仓库 `contents:write` + `pull_requests:write`）或 GitHub App；打 `automated` label，指定 reviewer。CI 上现有集成测试（`bin/stateless-validator/tests/integration.rs` 走 `TestFixtures::mainnet()`）就是验收标准，人只需 review + merge。

## 9. CLI 与运行模式

M1 已实现的 CLI（分支 `liquan/coverage-replayer-design`，`bin/coverage-replayer`）：

```
coverage-replayer backfill --from <A> --to <B>     # 区间重放并入库（断点续跑：已判定块自动跳过）
    --rpc-endpoint <urls> --witness-endpoint <urls>  # 对齐手册：https://mainnet.megaeth.com/rpc
    --genesis-file <path>                            # test_data/mainnet/genesis.json
    --data-dir <dir> [--workers N] [--fetch-concurrency F] [--symbol-filter mega_evm]
coverage-replayer set-cover --data-dir <dir> [--manifest-out <path>] [--incumbent-manifest <path>]
coverage-replayer report --data-dir <dir> [--path-filter mega-evm]   # llvm-cov 汇总（唯一用 llvm-cov 处）
coverage-replayer internal-worker …                # 隐藏：常驻 worker 子进程入口（backfill 自行 spawn）
```

M2 增补：`run`（常驻 lag 跟随）；M3/M4 增补：`pr-bot`。环境变量前缀 `COVERAGE_REPLAYER_`（对齐 validator 的 `STATELESS_VALIDATOR_` 惯例）。

## 10. 构建与部署

- 专用 profile（新增到根 `Cargo.toml`）：

```toml
[profile.coverage]
inherits = "release"
opt-level = 2
lto = "off"          # 覆盖率只关心"是否执行到"，不需要 release 的 thin-LTO/cgu=1
codegen-units = 16
```

- 构建：`RUSTFLAGS="-C instrument-coverage -Z coverage-options=branch" cargo build --profile coverage --bin coverage-replayer --features coverage --target "$(rustc -vV | sed -n 's/host: //p')"`（标准 profiler runtime 随插桩自动链接）。两个实测注意点：**不要**加 `-C link-dead-code`（强制单态化死代码里的非法泛型实例，revm 编译不过）；**必须显式 `--target`**（否则 RUSTFLAGS 会插桩 host 侧 proc-macro，每次 rustc 调用都往 cwd 撒 `default_*.profraw`）；
- M1 实测发现：对完整 covmap 出报告会触发 `llvm-cov` 的段错误（LLVM 在个别依赖文件的 instantiation-group 处理上有 bug）。`report` 子命令的对策是把 SOURCES 固定为 mega-evm 的 cargo checkout 目录（从 `Cargo.lock` 自动探测，可用 `--source-dir` 覆盖）——既绕开崩溃，也正是我们要的报告范围。位图热路径完全不受影响（不经过 llvm-cov）；
- 后续优化（非 v1）：`RUSTC_WRAPPER` 按 `CARGO_PKG_NAME` 只给 mega-evm 系 crate 加插桩，把 revm/salt 等热路径的插桩开销拿回来；
- 部署：单机 systemd 一个 unit（`run`）+ 两条 cron（`set-cover`→`pr-bot`、每日；`report` 按需）。可选第二个 unit 跑 `run --fetch-only`（仅拉取落 spool，不执行），用于重建二进制期间不中断拉取——同一 artifact，两个 unit；
- 观测（Prometheus，复用 stateless-common）：fetch lag、spool 深度、worker 吞吐/失败、sanity 不一致计数（**告警**）、pattern 总数、universe 大小、当前集合大小、上次 PR 时间。

## 11. 前期实验（状态与分工）

| #   | 实验                                                                                                                            | 结论 / 负责人                                                                                                  |
| --- | ------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| E1  | branch 插桩下，进程内逐块 reset→执行→写 profraw（常驻 worker 语义），产物能否被 llvm-profdata/llvm-cov 正常消费且含 branch 数据 | **本地已验证通过**（标准 runtime FFI 方案，见下）。附带发现：minicov 在 macOS 链接失败且对本设计并无必要，弃用 |
| E2  | `llvm-profdata merge --text` 提取非零 counter 位图，且两个不同输入的位图可区分                                                  | **本地已验证通过**（见下）                                                                                     |
| E3  | 插桩后 replay-only 的单块耗时（决定 worker 数与 backfill 时长预算）                                                             | **已有服务器正式数据**（mnet-tko，1001 块 @20.70M，~8.9M gas/块）：单块 worker avg **453ms** / p50 445 / p95 665 / max 1932；整体 **34.9 块/s**（~16 workers、fetch 32 并发，光路 fetch 无 EC 解码）→ 推算 100k 块 ≈ 48min、1M ≈ 8h、全历史 20.7M ≈ 7 天（单机，随核数线性扩展）。1001/1001 sanity 零失败；Linux 上 report（mega-evm SOURCES 范围）正常无段错误 |
| E4  | RPC 侧 witness 的保留窗口                                                                                                       | **已确认（@liquan）**：主网 RPC 可取 block 1 至最新块的全部 witness → window 归档取消，重扫直接 RPC backfill   |
| E5  | 跳过 EC 验证、从 wire 字节直接解出 kvs+levels                                                                                   | **已实现**（`stateless-core::LightWitnessFromSalt` 镜像解码 + `decode_witness_payload_light` / `get_witness_light`，fetcher 已切换）：6.3 MiB witness 的 bincode 解码 110ms→**1.4ms**（~80x wall、~700x 核时，单线程）；正确性由全量 mainnet fixtures 的字节精确一致性测试 + 真实 `.zst` 端到端测试 + 坏点流（full 必败/light 必过）锁定 |
| E6  | `.salt` envelope（`WitnessFileContent`）后续格式                                                                                | **决定（@liquan）**：改为 `.zst`（R2 witness binary format，即 `encode_witness_payload` 产物），后续单独 PR。PR bot 组装载荷时从 RPC 现拉完整 witness 再按该格式落盘（本地不存 raw） |

### E1/E2 本地实验记录（2026-07-08，macOS arm64，nightly-2026-02-03）

方法：最小 crate（**无任何依赖**），`RUSTFLAGS="-C instrument-coverage -Z coverage-options=branch"`，FFI 声明 `__llvm_profile_reset_counters` / `__llvm_profile_set_filename` / `__llvm_profile_write_file`；**单进程内连续执行两个"块"**（每块 reset → 执行 → 写 profraw），输入分别为 `0..10`（case a）与 `101..160`（case b，触达 `x>100 && x%7==3` 路径）。

结果（全部通过）：

- llvm-profdata / llvm-cov（nightly-2026-02-03 自带 llvm-tools）正常消费两个 profraw，**branch 数据存在**：case a `branches 3/6`、case b `branches 5/6`（regions 23/57 vs 27/57）；
- **进程内逐块 reset 语义正确**：先跑的 a 不含 b 的计数，b 也不含 a 残留——常驻 worker 串行多块的模型成立；
- `llvm-profdata merge --text` 文本 dump 直接解析出非零 counter 集合：目标函数 a=`[0,1,4,5]`、b=`[0,1,2,3,4,5]`，差集 `[2,3]` 恰是 `x>100` 真路径对应的 branch counter——**位图在 branch 粒度可区分，可直接作为集合覆盖的输入**，无需 llvm-cov 参与；
- 附带发现：minicov 0.3 在 macOS 上链接失败（`Undefined symbols: __start___llvm_prf_*`，其打包的 `InstrProfilingPlatformLinux.o` 依赖 ELF section 符号）。spike 当时在 Linux 上可用，但标准 runtime FFI 零依赖、与 rustc 的 LLVM 版本天然一致、macOS 本地开发亦可跑，故转为主选，minicov 不再引入。

### M1 E2E 记录（2026-07-08，macOS arm64，公共 RPC `mainnet.megaeth.com/rpc`）

- backfill `20717400..=20717599`（tip 附近 200 块，6 workers / 12 fetch 并发）：**200/200 成功，sanity（gas / receipts root / logs bloom）零失败**；wall 246s，fetch-bound——且经实测归因主要是**网络往返/下载**而非解码（见下一条），worker 大量空闲；
- **witness 解码实测**（salt v1.0.5 已含 #137 并行反序列化，`parallel` feature 经 `stateless-core/std → salt/default` 默认开启）：6.3 MiB / 65,358 commitments 的 bench witness（block 6906405），本机 14 核 **完整解码 ~119ms**、`LightWitness` 转换 ~0.5ms，与 PR #137 描述（14 核 ~108ms，9.8x）一致；`light_witness.rs` 注释里的 "~240ms" 为 #137 之前的旧数据。tip 常规块 witness 更小，解码远低于此；
- **E3 初步数据**：单块 worker 耗时（spool 加载 + replay + profraw + `llvm-profdata --text` + 位图提取，插桩后）avg **136ms** / p50 132 / p95 163 / max 256 → 单 worker ≈7 块/s，6 worker CPU 侧容量 ≈44 块/s。重扫吞吐的真正瓶颈在拉取/解码侧——服务器部署时加大 `--fetch-concurrency`、配多 witness endpoint 收益最大；
- pattern 判定：200 块 → 76 个 distinct pattern，universe = **1522 个非零 branch counter**（`mega_evm` 符号过滤后）；
- set-cover：**8 块覆盖 1522/1522**；report（mega-evm 源码范围）：regions 42.53%、functions 45.02%、lines 43.83%、**branches 29.87%**——tip 常规流量的覆盖上限明显，印证了"历史多样区块 + 持续跟随"的必要性；
- 踩坑记录：① `llvm-cov` 对全量 covmap 出报告会段错误（LLVM 对个别依赖文件 instantiation-group 处理的 bug）→ `report` 固定 SOURCES = mega-evm checkout（从 Cargo.lock 自动探测，`--source-dir` 可覆盖）；② `-C link-dead-code` 不可用（强制单态化死代码，revm const-eval 断言编译失败）；③ 并发解析同一合约 hash 时 tmp 文件名碰撞导致个别 fetch 失败，已用唯一化 tmp 名修复。

### 分片 merge + 覆盖率确定性（2026-07-09，服务器 24 万块 + 本地对照）

- **四机分片**：全历史 ~2000 万块单机 ~6 天(真实段)+ 压测段 6M–7M(~19s/块,~两周)。新增 `merge` 子命令把各机（同一插桩二进制、扫不相交区间）的 store 合并成一个。正确性关键：pattern 的位图用**每机各自的 dense 编号**（首见顺序不同 → 同一 counter 在 A 机是第 5 位、B 机第 8 位），直接 OR 会错；merge 通过 `源 dense → counter id（内容寻址，跨机稳定）→ 统一 dense` 重映射每个位图,再按 pattern key(= counter id 集合的 FxHash,同样跨机稳定)折叠。单测锁定"dense 顺序相反的两机"场景 + 顺序无关性;E2E 验证 merge(两分片)与顺序单跑同区间的 **universe 完全相同**。
- **覆盖率确定性实测**（同一 60 块区间，多种配置）：**universe 恒为 1454**（1 worker×3、4 worker、2 分片 merge,5 次独立运行全部 1454）;但 distinct pattern 数在 **29/30/31/32** 间抖动——**仅**多 worker/分片时抖动,单 worker 三次完全确定(29/29/29)。
  - 机制:单块覆盖本身确定(实测同一块冷/热重放位图字节一致),但 mega-evm/revm 有**按进程的缓存**(如 jumpdest 分析),命中/未命中走不同分支 → 一个块的精确位图取决于该 worker 进程此前处理过什么。**每个分支最终都会被某个块覆盖**,所以 universe 不变;只有 pattern 去重的粒度随并行度轻微波动。
  - **对交付物零影响**:universe(覆盖内容)、最小集合大小(6)、选块正确性都不受影响,只是 archive 里的 pattern 计数 ±1~2。因此**生产用多 worker(吞吐优先)完全正确**,不必为确定性牺牲吞吐锁 1 worker。
  - 一个理论边界(实践无碍):"缓存命中"分支只在进程处理过同一合约≥2 次后才覆盖——常驻 worker 长寿命(每个处理上千块),缓存充分预热,该分支正常覆盖;仅当 worker 频繁崩溃重启才会偏冷,全量运行不会遇到。

## 12. 开放问题

1. **是否复用 `stateless-core::pipeline`**：M1 按"简单 fetch 队列 + worker 池 + blocks 表断点"实现（replayer 不需要 advance/连续性/reorg 语义）；M2 常驻模式实现时再评估是否迁到 pipeline 统一。
2. **`validator-data/` 的定位**：本设计稿按指示放在 `validator-data/`，但注意该目录名与 README 示例的 validator `--data-dir`（运行时数据库）相同，且被根 `.gitignore` 忽略（本文件是 `git add -f` 强制跟踪的）。建议二选一：文档移到 `docs/`，或调整 `.gitignore`（如改为忽略 `validator-data/**` 但豁免 `*.md`）。后续 manifest/归档索引等运营数据是否也归这里（vs 全部只进 `test_data/mainnet`），一并待定。
3. **多链**：目前只针对 mainnet；testnet 若也要，同一服务多实例 + data-dir 隔离即可，manifest/test_data 路径参数化。

## 13. 里程碑

- **M0（✅）**：E1/E2 冒烟（✅）、main 代码走读（✅）、E4/E6 确认（✅）；
- **M1（代码已落地，本地 E2E ✅，分支 `liquan/coverage-replayer-design`）**：`bin/coverage-replayer`——backfill 模式全链路（RPC → spool → 常驻 worker 池 → branch 粒度位图 → pattern 判定/晋升 → set-cover → report），fmt/clippy/sort/单测/fixture 集成测试全过，对现有 crates 零改动；本地 200 块主网 E2E 全链路通过（数据见 §11），剩余动作：服务器部署 + 大区间正式重扫；
- **M2**：常驻 `run` 模式——lag 跟随、指标与告警、断点续跑；
- **M3**：manifest 落 `test_data/mainnet` + `pr-bot --dry-run`（产出 PR 内容但不真提）；
- **M4**：pr-bot 上线（机器账号、频控、CI 验收）+ 运维 runbook；旧 spike 分支归档。
