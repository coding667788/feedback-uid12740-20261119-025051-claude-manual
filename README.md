# 离线服务分区策略审计器

在滚动切换（rolling cutover）过程中，离线审计两组防火墙规则版本（`old`/`new`）
在每一个中间状态下的实际连通性，求一条从全量旧规则到全量新规则、每步只切换一个
部署组且全程满足必需/禁止连通性约束的合法序列，并给出每一步的双向许可端口差分
与规则出处。

仅依赖 Python 3.12 标准库，纯 CPU，离线运行。

## 运行方式

```bash
# 审计（输入 cases.json，输出 result.json）
python -m solution --input cases.json --output result.json

# 自动化测试
python -m unittest discover -s tests -v
```

## 目录结构

```
solution/            被测包
  intervals.py       闭整数区间 / 带出处片段代数（扫描线，不逐端口展开）
  model.py           领域对象与选择器
  parser.py          cases.json 载入与严格校验
  policy.py          单端/双向许可求值、显式拒绝优先、约束校验
  search.py          DAG 可达枚举、字典序最小序列、无解阻断证据
  diff.py            每步双向许可端口片段差分与规则出处
  cli.py             命令行入口
tools/gen_cases.py   cases.json 的可重放生成器
tests/
  oracle.py          独立朴素预言机（逐点集合 + 全排列/BFS，不导入被测求值逻辑）
  test_*.py          单元/穷举/端到端测试
cases.json           10 个合成场景（由 tools/gen_cases.py 生成）
```

## 输入结构

顶层支持单 case 对象，或批量文档：

```json
{ "schema_version": 1, "cases": [ { ...case... } ] }
```

单个 case 字段：

| 字段 | 说明 |
|---|---|
| `case_id` | 字符串，唯一标识 |
| `port_domain` | `[lo, hi]`，闭整数端口域，默认 `[0,65535]` |
| `services` | 服务 id 列表，每个服务至少有一个实例 |
| `groups` | 部署组 id 列表，**最多 16 个** |
| `instances` | `{id, service, group, labels[]}`，实例归属唯一服务与组 |
| `depends_on` | `{组: [前置组...]}`，前置组必须先切换；必须构成 DAG |
| `rules` | 规则列表，见下 |
| `constraints` | 全阶段连通性约束列表，见下 |

规则：

```json
{
  "id": "r1",
  "version": "old",            // old | new
  "action": "allow",           // allow | deny，显式 deny 优先
  "protocol": "tcp",           // 具体协议或 "*" 通配
  "side": "outbound",          // outbound=源端出站, inbound=目的端入站
  "source":      { "service": "web", "labels": ["tier=front"] },
  "destination": "all",        // "all"/"*"/null 表示任意实例
  "ports": [[10, 100]]         // 一个或多个闭区间，自动归一化合并
}
```

选择器省略的维度不限制；`labels` 为 AND 子集匹配；`source`/`destination`
也可写成 `"all"`、`"*"` 或 `null`。

约束（初始态与全量目标态同样参与校验）：

```json
{
  "id": "c1",
  "kind": "required",          // required | forbidden
  "source_service": "web",
  "destination_service": "db",
  "protocol": "tcp",
  "ports": [[10, 12], [443, 443]]
}
```

- `required`：**约束内每个已声明端口**都必须落在实际双向许可内（逐实例对）；
- `forbidden`：约束内每个已声明端口都必须不在实际双向许可内，任一相交即违规。

## 求值语义

1. 实例在状态 `mask` 下采用的规则版本，由其所属组是否已切换决定；
2. 单端许可：选取该版本、该侧（出站/入站）、协议匹配且两端选择器都匹配的规则，
   对其闭区间做扫描线合并，**显式 `deny` 优先**——某端口只要落在任一 deny 上，
   即使被 allow 覆盖也不可连通；
3. 实际双向许可 = 源实例出站许可 ∩ 目的实例入站许可，片段出处同时携带两侧规则 id；
4. 全程只在区间端点上运算，输出片段数随规则数增长，**不随端口域宽度增长**，
   生产代码中不存在对端口的逐点展开（无 `range(port)` 形式）。

## 序列搜索

- 状态用位掩码表示，第 i 位对应字典序第 i 个组；
- 合法邻接：切换一个未切换、且全部 DAG 前置组均已切换的组；
- 合法状态：通过全部约束（初始掩码 `0` 与全量掩码同样校验）；
- 有解：按组名字典序深度优先，第一条到达全量的路径即**字典序最小合法序列**；
- 无解：报告全部可达合法状态中**完成组数量最多**者，并列时按完成组排序列表的
  字典序打破；并给出该状态每个未切组的阻断证据：
  - `dependency`：仍有前置组未切换（附 `missing_prerequisites`）；
  - `constraint`：切换后的新状态违反约束（附具体违规列表）。

## 错误码

输入类错误以退出码 `2` 返回，并在输出 JSON 中带 `error_code`；
搜索不到计划不是输入错误，结果 `status` 为 `no_plan`，退出码 `0`。

| 错误码 | 含义 |
|---|---|
| `E_IO` | 输入文件无法读取或输出路径不可写 |
| `E_JSON` | 不是合法 JSON，或顶层 schema 不符 |
| `E_SCHEMA` | 字段缺失、类型错误、取值非法（含组数 > 16、区间倒置） |
| `E_DOMAIN` | 端口越界、未知服务/组引用、服务无实例 |
| `E_DAG_CYCLE` | 依赖图有环、自依赖或引用未知组 |
| `E_RULE` | 规则动作/侧/版本非法或规则 id 重复 |
| `E_INITIAL` | 初始状态即违反约束 |
| `E_FINAL` | 全量目标状态违反约束，计划不可能存在 |

## 边界示例

- 闭区间相邻合并：`[1,2]` 与 `[3,4]` 融合为 `[1,4]`；
- 单端口拒绝：允许 `[1,50]` 叠加 `deny [25,25]` → 许可 `[1,24] ∪ [26,50]`；
- 单端点自连接：单实例对自身的出站/入站交集（case 05）；
- 多端口 required：声明 `[1,2]` 与 `[4,4]` 时，缺任一端口即违规；
- 协议通配：`protocol="*"` 的 allow 对任意协议生效，但具体协议的 deny 仍优先。

## 场景覆盖（cases.json）

| case | 场景 | 期望结果 |
|---|---|---|
| 01 | 混合版本瞬时暴露，唯一合法顺序 db→web | plan_found `[db, web]` |
| 02 | 两组并列拒绝，初始态即死路 | no_plan，最佳完成 0 组 |
| 03 | 局部可行步骤通往死路（自由组可切、锁组卡死） | no_plan，最佳完成 g3,g4 |
| 04 | 同一步新增 300-400、下一步断流 13-79 | plan_found，含双向差分 |
| 05 | 单端点自连接、闭区间边界 deny | plan_found `[g0]` |
| 06 | 全量目标态违规 | error `E_FINAL` |
| 07 | 初始态违规 | error `E_INITIAL` |
| 08 | DAG 前置顺序 | plan_found `[gb, gc, ga]` |
| 09 | DAG 依赖阻断 + 约束阻断并存 | no_plan，含 dependency/constraint 证据 |
| 10 | 自由组切完后锁组无法推进的死路 | no_plan，最佳完成 gc |

## 测试与独立性

- `tests/oracle.py` 是**完全独立**的朴素判定器：逐端口集合求许可、全排列枚举合法
  序列、独立 BFS 求可达状态，不导入 `solution` 的任何求值/搜索逻辑；
- 全部期望值要么手工给定，要么由该预言机独立算出，**不从被测实现反推**；
- `test_exhaustive.py` 用固定随机种子生成 300 个小 case（1–4 组、窄端口域）做穷举
  交叉验证，并含一个 16 组规模 sanity（状态空间 2^16，BFS 不依赖阶乘）。

## 实测结果

Windows 原生 Python 3.12.8（仅标准库、CPU）：

```
$ python -m unittest discover -s tests -v
Ran 47 tests in <1s
OK

$ python -m solution --input cases.json --output result.json
审计完成：10 个 case，plan_found=4，no_plan=4，error=2；结果已写入 result.json
```

`error=2` 对应 case 06（E_FINAL）与 case 07（E_INITIAL）这两个专门的输入语义场景，
属预期结果而非运行失败；CLI 退出码仍为 0。
