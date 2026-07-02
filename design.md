# Kona Validator replay_block 替换方案

## 2026-06-30

### 背景

本笔记用于评估 `stateless-validator::replay_block` 是否可以在外部接口不变的前提下，改为复用 Kona 的 `KonaExecutor::execute_payload` 执行路径。当前内容是设计方案，不代表已修改代码。

### 当天进展

- 明确 `execute_payload` 依赖已经通过 `update_safe_head(parent_header)` 初始化的 `StatelessL2Builder`，不能只做 `block -> payload_attrs` 的浅转换。
- 梳理了 `KonaReplayProvider`、`parent_header`、`TrieDBProvider`、`BlockBuildingOutcome` 到 `replay_block` 返回值之间的关键适配点。
- 给出三种 `BundleAccount`/artifacts 处理方案，并推荐扩展 `BlockBuildingOutcome` 或等价 artifacts，使一次 `execute_payload` 后可完整构造旧返回值。
- 补齐 `trace_writer`、no_std/zkVM、依赖版本和最小可验证原型的风险判断。

### 后续动作

- 用最小原型验证 `KonaReplayProvider + execute_payload` 生成的 artifacts 是否能匹配 claimed block header。
- 确认是否允许扩展 Kona artifacts 以暴露 bundle state 与 state read/write stats。
- 如果 `trace_writer` 仍是硬需求，需要单独设计 inspector 支持或明确返回不支持错误。

## 目标

将 `stateless-validator::replay_block` 的内部执行逻辑替换为 Kona 的 `KonaExecutor::execute_payload`。

外部接口保持不变：

```rust
pub fn replay_block<DB, ENV, E>(
    chain_spec: &ChainSpec,
    block: &Block<OpTransaction>,
    db: &DB,
    env_oracle: ENV,
    #[cfg(feature = "std")] trace_writer: Option<Box<dyn Write>>,
) -> Result<(HashMap<Address, BundleAccount>, BlockExecutionOutput), ValidationError>
```

新的内部语义是：

```text
replay_block inputs
  -> 构造 execute_payload 所需输入
  -> KonaExecutor::new(...)
  -> update_safe_head(parent_header)
  -> execute_payload(payload_attrs)
  -> BlockBuildingOutcome { header, execution_result }
  -> 转换为 replay_block 原返回值
```

本方案只讨论设计可行性和落地路径，不修改代码。

## 结论

方案可行，但需要补齐一个适配层。

`KonaExecutor::execute_payload` 本身不是独立函数。它依赖一个已经通过 `update_safe_head(parent_header)` 初始化过的 `StatelessL2Builder`，而 builder 又依赖 `TrieDBProvider` 从 witness 中读取：

- trie node
- bytecode preimage
- parent/header preimage
- serialized `SaltWitness`

因此，`replay_block` 不能只把 `block` 转成 `payload_attrs` 就直接调用。它必须先从现有 `db`/witness 上下文构造一个 Kona provider。

## 输入转换

### block -> OpPayloadAttributes

`execute_payload` 的核心输入是 `OpPayloadAttributes`。可以按 `kona_executor::test_utils::payload_attrs_from_block` 的逻辑从 claimed block 构造：

- `timestamp <- block.header.timestamp`
- `prev_randao <- block.header.mix_hash`
- `suggested_fee_recipient <- block.header.beneficiary`
- `parent_beacon_block_root <- block.header.parent_beacon_block_root`
- `transactions <- block.transactions` 的完整 encoded tx bytes
- `gas_limit <- block.header.gas_limit`
- `eip_1559_params / min_base_fee` 按 MegaETH/Kona 现有 helper 填充

前置要求：`block.transactions` 必须是 `BlockTransactions::Full`，否则仍返回 `ValidationError::BlockIncomplete`。

### block/db -> parent_header

`KonaExecutor::update_safe_head` 需要 parent sealed header。`replay_block` 当前只有当前 block header，缺 parent header 完整字段。

可行方案：

1. 从新的 `KonaReplayProvider` 适配层读取 parent header。
2. parent header hash 必须等于 `block.header.parent_hash`。
3. parent header number 必须等于 `block.header.number - 1`。
4. parent header state root 必须等于 `SaltWitness::state_root()`。

如果现有 witness 数据只包含 parent state root 而没有 parent header，那么不能正确初始化 `KonaExecutor`。这不是实现细节，是 execute_payload 路径的真实输入要求。

### db -> TrieDBProvider

`KonaExecutor` 的 provider 需要实现：

```rust
trait TrieDBProvider: TrieProvider {
    fn trie_node_by_hash(&self, key: B256) -> Result<TrieNode, Self::Error>;
    fn bytecode_by_hash(&self, code_hash: B256) -> Result<Bytes, Self::Error>;
    fn header_by_hash(&self, hash: B256) -> Result<Header, Self::Error>;
    fn salt_witness_by_state_root(
        &self,
        block_number: u64,
        parent_hash: B256,
        state_root: B256,
        payload_attributes_hash: B256,
    ) -> Result<Bytes, Self::Error>;
}
```

stateless-validator 当前的 `WitnessDatabase` 实现的是 `DatabaseRef`，不是 `TrieDBProvider`。所以需要新增一个 provider adapter，例如：

```rust
struct KonaReplayProvider<'a, DB> {
    block: &'a Block<OpTransaction>,
    db: &'a DB,
    parent_header: Header,
    salt_witness_bytes: Bytes,
    trie_nodes: ...,
    bytecodes: ...,
}
```

最理想的落地方式是让 `WitnessDatabase` 或其内部 witness 类型暴露足够信息，然后实现：

```rust
impl TrieProvider for KonaReplayProvider<'_, WitnessDatabase<'_, Witness>> { ... }
impl TrieDBProvider for KonaReplayProvider<'_, WitnessDatabase<'_, Witness>> { ... }
```

如果想保持 `replay_block` 参数列表不变，但允许收紧泛型约束，可以让 `DB` 增加一个内部 trait：

```rust
trait KonaReplaySource {
    fn parent_header(&self, block: &Block<OpTransaction>) -> Result<Header, ValidationError>;
    fn kona_provider(&self, block: &Block<OpTransaction>) -> Result<KonaReplayProvider<'_>, ValidationError>;
}
```

然后 `replay_block` 的参数列表不变，但实现要求：

```rust
DB: DatabaseRef<Error = E> + KonaReplaySource + Debug
```

这会改变泛型能力，但不改变函数调用形态。当前实际调用者是 `WitnessDatabase`，所以这是可控的。

## execute_payload 调用

`KonaExecutor::execute_payload` 是 async trait 方法，但当前实现内部实际调用同步的 `StatelessL2Builder::build_block`：

```rust
async fn execute_payload(
    &mut self,
    attributes: OpPayloadAttributes,
) -> Result<BlockBuildingOutcome, Self::Error> {
    self.inner.as_mut().map_or_else(
        || Err(kona_executor::ExecutorError::MissingExecutor),
        |e| e.build_block(attributes),
    )
}
```

因为 `replay_block` 必须保持同步接口，需要在内部阻塞等待：

- std 构建：使用 `futures::executor::block_on` 或项目已有 blocking helper。
- no_std/zkVM 构建：需要确认是否允许同步 poll 这个 future。由于当前 future 不真正 await I/O，理论上可以用一个极小的 poll executor，但实现时要避免引入 host-only runtime。

建议把这一步封装成 helper：

```rust
fn execute_payload_sync<E>(
    executor: &mut E,
    attrs: OpPayloadAttributes,
) -> Result<BlockBuildingOutcome, ValidationError>
where
    E: kona_driver::Executor,
```

这样如果未来 `execute_payload` 真正异步化，只需要替换这个 helper。

## artifacts -> replay_block 返回值

`execute_payload` 返回：

```rust
BlockBuildingOutcome {
    header: Sealed<Header>,
    execution_result: BlockExecutionResult<MegaReceiptEnvelope>,
}
```

`replay_block` 需要返回：

```rust
(HashMap<Address, BundleAccount>, BlockExecutionOutput)
```

### BlockExecutionOutput

这一部分可以直接从 artifacts 构造：

```text
receipts_root <- artifacts.header.receipts_root
logs_bloom    <- artifacts.header.logs_bloom
gas_used      <- artifacts.header.gas_used
```

或者从 `artifacts.execution_result.receipts` 重新计算：

```text
receipts_root <- calculate_receipt_root(receipts)
logs_bloom    <- OR(receipt.bloom)
gas_used      <- execution_result.gas_used 或最后一个 receipt cumulative gas
```

推荐使用“双算并断言一致”：

1. 从 receipts 计算 `receipts_root/logs_bloom/gas_used`。
2. 与 `artifacts.header` 对比。
3. 返回计算值。

这样可以尽早发现 Kona artifacts 内部 header sealing 和 execution result 不一致的问题。

`state_reads/state_writes` 目前旧实现从 `StateBuilder` 的 cache/bundle_state 统计。`BlockBuildingOutcome` 不暴露 bundle/cache，所以不能等价恢复。

可选策略：

- 短期：填 `0`，并在文档/指标中说明 execute_payload path 不提供访问统计。
- 中期：扩展 Kona artifacts，额外返回 execution stats。
- 长期：让 `KonaExecutor` 返回一个 validation/replay artifact，包含 bundle state 和 stats。

如果现有上层只把 stats 用于观测，短期填 `0` 可接受；如果测试断言这些统计，则需要扩展 artifacts。

### HashMap<Address, BundleAccount>

这是最大转换点。

旧 `replay_block` 返回 `state.bundle_state.state`，后续 `validate_block` 用它做两件事：

1. 提取 L2-to-L1 message passer 的 storage updates，验证 withdrawals root。
2. 展平 account/storage changes，执行 SALT two-phase update，计算 state root。

但 `execute_payload` 已经在 Kona builder 内部完成了：

- merge state transitions
- two-phase SALT update
- new SALT state root
- withdrawal storage root update
- seal header

`BlockBuildingOutcome` 不暴露 `BundleAccount`。因此有三种设计选择。

### 方案 A：构造空 accounts，迁移 validate_block 后半段

`replay_block` 返回：

```rust
Ok((HashMap::new(), output))
```

然后 `validate_block` 后半段不再依赖 accounts 去重算 state root/withdrawals root，而是直接比较：

```text
artifacts.header.state_root       == block.header.state_root
artifacts.header.withdrawals_root == block.header.withdrawals_root
artifacts.header.receipts_root    == block.header.receipts_root
artifacts.header.logs_bloom       == block.header.logs_bloom
artifacts.header.gas_used         == block.header.gas_used
artifacts.header.hash             == block.header.hash
```

问题：这会要求 `replay_block` 的返回值携带 artifacts header。由于返回类型不能变，需要把 artifacts 临时放到 side channel 或扩展 `BlockExecutionOutput`，但这又改变类型。

结论：如果严格不改 `validate_block` 和返回类型，方案 A 不完整。

### 方案 B：扩展 KonaExecutor artifacts，返回 BundleAccount

修改 Kona execution artifacts，让 `execute_payload` 返回或附带 bundle state：

```rust
pub struct BlockBuildingOutcome {
    pub header: Sealed<Header>,
    pub execution_result: BlockExecutionResult<MegaReceiptEnvelope>,
    pub bundle_state: HashMap<Address, BundleAccount>,
    pub state_reads: usize,
    pub state_writes: usize,
}
```

然后 `replay_block` 可以真正构造旧返回值：

```rust
let output = BlockExecutionOutput {
    receipts_root,
    logs_bloom,
    gas_used,
    state_reads: artifacts.state_reads,
    state_writes: artifacts.state_writes,
};

Ok((artifacts.bundle_state, output))
```

优点：

- `replay_block` 返回语义最接近旧实现。
- `validate_block` 后半段基本不用改。
- 可以继续独立验证 withdrawals root 和 state root。

缺点：

- 需要改 mega-kona 的 `BlockBuildingOutcome`，影响序列化、rkyv、缓存和现有测试。
- 需要确认 bundle state 是否适合暴露到 zkVM journal/cache 中，避免 artifacts 变得过大。

### 方案 C：新增 Kona replay artifact，但 replay_block 仍转换旧返回

不直接污染 `BlockBuildingOutcome`，而是在 Kona executor 内部新增 replay 专用结果：

```rust
pub struct KonaReplayArtifacts {
    pub outcome: BlockBuildingOutcome,
    pub bundle_state: HashMap<Address, BundleAccount>,
    pub state_reads: usize,
    pub state_writes: usize,
}
```

然后 `KonaExecutor::execute_payload` 仍返回 `BlockBuildingOutcome`，但 replay path 使用一个 wrapper 收集 bundle state。

问题：用户要求必须使用 `execute_payload` 替换，所以 replay path 的主执行必须调用 `execute_payload`。如果 bundle state 只能从另一个 API 获得，就变成双执行或旁路执行，不符合要求。

除非 `execute_payload` 内部把最近一次 replay artifacts 暂存在 executor 中：

```rust
let artifacts = executor.execute_payload(attrs)?;
let replay_artifacts = executor.take_last_replay_artifacts();
```

但这需要改 `KonaExecutor` 状态，也比方案 B 更隐式。

## 推荐方案

推荐采用方案 B：扩展 `BlockBuildingOutcome` 或在其旁边增加等价可公开字段，使 `execute_payload` 一次执行后能完整构造 `replay_block` 原返回值。

推荐最终数据流：

```text
replay_block
  -> require BlockTransactions::Full
  -> attrs_from_block(block)
  -> provider = KonaReplayProvider::from(db, block, chain_spec)
  -> parent_header = provider.parent_header(block.header.parent_hash)
  -> executor = KonaExecutor::new(rollup_config, provider.clone(), NoopTrieHinter, LazyMegaEvmFactory::default(), None)
  -> executor.update_safe_head(parent_header.seal_slow())
  -> artifacts = execute_payload_sync(&mut executor, attrs)
  -> verify artifacts.header fields against claimed block.header
  -> output = BlockExecutionOutput::from(artifacts.execution_result/header/stats)
  -> accounts = artifacts.bundle_state
  -> return (accounts, output)
```

## replay_block 内部校验

即使 `validate_block` 后面还会比较 roots，新的 `replay_block` 内部也应该做一些基本校验，帮助尽早定位：

- `artifacts.header.number == block.header.number`
- `artifacts.header.parent_hash == block.header.parent_hash`
- `artifacts.header.timestamp == block.header.timestamp`
- `artifacts.header.transactions_root == block.header.transactions_root`
- `artifacts.header.receipts_root == block.header.receipts_root`
- `artifacts.header.logs_bloom == block.header.logs_bloom`
- `artifacts.header.gas_used == block.header.gas_used`
- `artifacts.header.state_root == block.header.state_root`
- `artifacts.header.withdrawals_root == block.header.withdrawals_root`
- `artifacts.header.hash() == block.header.hash`

这些校验失败应映射到现有 `ValidationError`，或者新增：

```rust
KonaExecutionMismatch {
    field: &'static str,
    expected: B256,
    actual: B256,
}
```

## 需要新增或调整的错误类型

建议新增：

```rust
KonaProviderConstructionFailed(...)
KonaExecutePayloadFailed(...)
KonaHeaderMismatch { field, expected, actual }
KonaReplayStatsUnavailable
```

其中 `KonaReplayStatsUnavailable` 只在 state read/write 必须精确时需要；如果允许统计填 0，则不需要。

## trace_writer 处理

旧 `replay_block` 支持 `trace_writer`，走 `create_executor_with_inspector`。

`KonaExecutor::execute_payload` 当前接口没有 trace writer 参数。因此替换后有三种选择：

1. 暂时不支持 trace writer：如果传入 `Some(writer)`，返回明确错误。
2. 在 `KonaExecutor`/`StatelessL2Builder` 中增加 inspector 支持。
3. 在 provider/env 层保留 trace 开关，但实际执行仍无 trace。

推荐短期选择 1，避免用户以为 trace 生效。

## no_std / zkVM 可行性

需要特别检查：

- `execute_payload_sync` 不能依赖 tokio runtime。
- `KonaReplayProvider` 不能依赖 RocksDB、文件系统或 host-only API。
- 如果要序列化 `SaltWitness` 给 `salt_witness_by_state_root`，使用 `bincode`/`bincode2` 版本必须和 Kona builder 期望一致。
- `BlockBuildingOutcome` 扩展 bundle state 后，rkyv 序列化和 zkVM 内存占用需要评估。

## 依赖版本要求

stateless-validator 与 mega-kona 必须对齐这些依赖：

- `mega-evm`
- `salt`
- `revm`
- `alloy-*`
- `op-alloy-*`
- `kona_executor`
- `kona_proof`

否则 `BundleAccount`、receipt envelope、transaction type、`Bytecode` 类型很容易不兼容。

## 落地步骤

1. 在文档和测试中固定目标版本组合。
2. 给 stateless-validator 增加 `kona_executor/kona_proof/kona_megaevm/kona_mpt/kona_genesis` 依赖。
3. 实现 `KonaReplayProvider`，从现有 witness/db 上下文提供 `TrieDBProvider` 能力。
4. 实现 `block_to_payload_attrs`，对齐 `payload_attrs_from_block`。
5. 实现 `execute_payload_sync`。
6. 扩展 `BlockBuildingOutcome` 或等价 artifacts，使 `execute_payload` 暴露 bundle state 和 stats。
7. 在 `replay_block` 内切换为 execute_payload path。
8. 加入 header/artifact 一致性校验。
9. 跑同一批 fixture，对比旧 replay path 和新 execute_payload path 的：
   - block hash
   - state root
   - withdrawals root
   - receipts root
   - logs bloom
   - gas used
   - bundle state plain key updates

## 风险点

- 如果不扩展 artifacts，无法从 `BlockBuildingOutcome` 无损还原 `HashMap<Address, BundleAccount>`。
- 如果没有 parent header，无法正确调用 `update_safe_head`。
- 如果 `replay_block` 必须 no_std，async-to-sync helper 需要专门实现。
- 如果 trace writer 是硬需求，当前 `execute_payload` 接口不够。
- 如果版本不对齐，类型层面可能无法把 Kona artifacts 转回 stateless-validator 的返回类型。

## 最小可验证原型

最小原型可以先不接入完整 `validate_block`，只验证 execute_payload 的 artifacts 是否能匹配 claimed block：

```text
input: parent block + claimed block + SaltWitness + MPT witness + bytecodes
  -> KonaReplayProvider
  -> replay_block_execute_payload_only
  -> artifacts
  -> compare artifacts.header with claimed block.header
```

这个原型能回答两个关键问题：

1. 参数转换是否足够调用 `execute_payload`。
2. Kona artifacts 是否能和 claimed block 完全一致。

原型通过后，再处理 `replay_block` 原返回值中的 `BundleAccount` 和 stats。

#OP-Stack/fault-proof
