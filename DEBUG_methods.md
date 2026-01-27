Stateless实现debug_*/trace_*类RPC
需求背景
debug_*/trace_*类方法需要大量的block execution，当前使用RPC node服务此类方法有以下两个严重问题：
- 需要消耗大量的计算资源，但是RPC node由于比较重（heavy）不容易进行弹性扩容。
- 如果block tag为历史区块，则需要查询历史状态，这类操作在PRC node的DB上十分低效。
解决方案
单独为此类RPC实现一个RPC server，并使用block data和witness来支持任意历史区块的重执行。
架构
1. 顶层接口组件
RPC Server（RPC 服务器）：

作为对外入口，接收外部请求（图顶有输入箭头表示）；
向下发起请求执行区块（Request block execution），调用核心执行组件；
接收核心执行组件返回的交易痕迹（Transaction Traces），并向外部返回结果。
2. 核心执行组件
Stateless Executor（无状态执行器）：

接收 RPC Server 的 Request block execution（请求执行区块）；
向数据提供组件发起请求区块（Request block）；
接收数据组件返回的 block data & witness（区块数据与见证）后执行；
向 RPC Server 返回 Transaction Traces（交易痕迹，执行结果）。
3. 数据提供组件
BlockProvider（区块提供者）：

接收 Stateless Executor 的 Request block（请求区块）；
从两个数据源获取数据：
从 Cloudflare KV Store（Cloudflare 键值存储）获取区块数据；
从 Witness Generator（见证生成器）获取见证数据；
整合后向 Stateless Executor 返回 block data & witness（区块数据与见证）。
4. 外部依赖组件
Cloudflare KV Store：区块数据存储服务，向 BlockProvider 提供区块数据；
Witness Generator：见证数据生成服务，向 BlockProvider 提供见证数据。

优化事项
1. Witness validation可能不是必须的（Trustful vs Trustless）
2. BlockProvider需要pre-fetch block data/witness
3. revm_inspectors::TracingInspector的结果是多个RPC公用的，也许可以为每个block做cache
4. 多个几乎同时收到的、需要执行相同block的RPC应该保证只执行一次block
5. 选用合适的RPC response compression方式