<div align="right"><sub><a href="./README.en.md">English</a>&nbsp;&nbsp;⇄&nbsp;&nbsp;<b>简体中文</b></sub></div>

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="./assets/hero-dark.svg">
    <source media="(prefers-color-scheme: light)" srcset="./assets/hero-light.svg">
    <img src="./assets/hero-light.svg" width="880" alt="CanaryProbe — 给读不到源码的闭源 coding agent 埋下诱饵，一旦它去探测就即时告警">
  </picture>
</p>

<p align="center"><sub>给你读不到源码的闭源 <b>coding agent</b> 埋诱饵主机名和假凭证，一旦二进制去解析或连接它，就在运行期即时告警并留下审计证据。</sub></p>

<p align="center">
  <a href="./LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT"></a>
  <a href="https://github.com/SuperMarioYL/canaryprobe/releases"><img src="https://img.shields.io/github/v/release/SuperMarioYL/canaryprobe" alt="Latest release"></a>
  <a href="https://github.com/SuperMarioYL/canaryprobe/actions/workflows/ci.yml"><img src="https://github.com/SuperMarioYL/canaryprobe/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/badge/python-3.12%2B-3776AB.svg" alt="Python 3.12+">
  <img src="https://img.shields.io/badge/coding--agent-supply--chain-D62828.svg" alt="coding-agent supply-chain security">
</p>

**把「这个 coding agent 有没有偷偷外联」从一次次反编译，变成一个可核验的 yes/no 事件。**

CanaryProbe 是一个**诱饵探针（honeytoken tripwire）**：你在闭源 coding agent 能触达的环境里种下一个**没有任何正常代码路径会去碰的**诱饵主机名和假凭证；一旦那个你读不到源码的二进制去**解析**或**连接**它，探针在运行期立刻打出红色 `TRIPPED` 告警，并向审计日志追加一条不可篡改的 JSONL 记录。

---

## 目录

- [为什么需要它](#为什么需要它)
- [架构](#架构)
- [安装](#安装)
- [快速开始](#快速开始)
- [用法](#用法)
- [演示](#演示)
- [配置](#配置)
- [付费版本](#付费版本)
- [路线图](#路线图)
- [许可证](#许可证)

---

## 为什么需要它

<img src="https://api.iconify.design/tabler:shield-lock.svg?color=%230071E3&width=24" height="22" align="absmiddle" alt=""> **为什么需要它**

信创 / 等保 2.0 的 air-gap 部署里，越来越多团队把闭源 coding agent 对接到本地 Qwen / GLM / DeepSeek 端点（`ANTHROPIC_BASE_URL=http://localhost:...`）。合规要求「数据不出境」必须被**证明**，而不是被假设——可你读不到那个二进制的源码。今天要发现它有没有偷偷外联，唯一的办法是**逐版本反编译**：r/LocalLLaMA 那次 XOR-91 拆解，就是把一份主机名黑名单 Base64 解码、再用密钥 91 异或解密，才发现它指向了一批中国公司的域名。

CanaryProbe 把这件事翻过来：**与其反编译，不如设陷阱。** 诱饵是没有任何合法路径会触碰的值，所以「二进制碰了诱饵」这个事件本身就是**意图外联**的确凿信号——这正是它区别于「出口白名单」的地方：白名单记录*流量*、回答「这个主机允不允许」；CanaryProbe 回答「它探测了一个它本不该知道的主机吗」。

## 架构

<img src="https://api.iconify.design/tabler:topology-star-3.svg?color=%230071E3&width=24" height="22" align="absmiddle" alt=""> **架构**

单个 Python 包，`watch` 是一个进程里的两条传感线程，无任何外部服务、无云、无控制面。

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="./assets/atlas-dark.svg">
    <source media="(prefers-color-scheme: light)" srcset="./assets/atlas-light.svg">
    <img src="./assets/atlas-light.svg" width="880" alt="架构：init 种诱饵；watch 用 DNS + TCP 两个传感器汇入 alarm 与 audit.jsonl；report 读审计日志生成 report.md">
  </picture>
</p>

- **`sensor_dns.py`** —— 只对诱饵区（zone）**权威**的小型 DNS 服务器：一次解析就是一次触发；用回环 sinkhole 地址应答，让解析*成功*（这样 agent 可能进一步去*连接*，把 TCP 传感器也触发）。
- **`sensor_conn.py`** —— TCP 监听器：任何落到诱饵 bind 的连接都是一次触发；还会 peek 首个数据块，把 agent 试图带上的**假凭证**记为观测值。
- 两个传感器都是**用户态**——内核 / eBPF 级拦截明确不在 v0.1 范围内。

## 安装

<img src="https://api.iconify.design/tabler:package.svg?color=%230071E3&width=24" height="22" align="absmiddle" alt=""> **安装**

```bash
pip install canaryprobe
```

## 快速开始

<img src="https://api.iconify.design/tabler:rocket.svg?color=%230071E3&width=24" height="22" align="absmiddle" alt=""> **快速开始**

三条命令，从冷启动到抓到第一次探测：

```bash
canaryprobe init          # ① 生成诱饵主机名 + 假凭证 + 签名清单，打印注入指引
canaryprobe watch         # ② 武装 DNS + TCP 传感器（另开一个终端）
canaryprobe report        # ③ 生成签名的 clean / TRIPPED 证据文件
```

在 `watch` 与 `report` 之间，让 coding agent 去触碰诱饵即可。想在没有真实 agent 的情况下先看到「抓到」的瞬间，用内置模拟器：

```bash
canaryprobe simulate-trip --sensor dns    # 模拟一次诱饵解析
canaryprobe simulate-trip --sensor conn   # 模拟一次带假凭证的连接
```

<details>
<summary>watch 抓到探测时的样子</summary>

```
╭──────────  TRIPPED — decoy touched  ──────────╮
│    decoy  dcy_ab12cd34                         │
│ observed  internal-prod-db-42.corp.local       │
│   sensor  DNS                                  │
│   source  127.0.0.1:60809                      │
│     time  2026-07-03T11:22:35.467097+00:00     │
╰─ a coding agent probed a host it had no busin ─╯
```

同时 `audit.jsonl` 追加一行：

```json
{"decoy_id":"dcy_ab12cd34","observed_value":"internal-prod-db-42.corp.local","sensor":"dns","src":"127.0.0.1:60809","ts":"2026-07-03T11:22:35.467097+00:00","verdict":"TRIPPED"}
```

</details>

## 用法

<img src="https://api.iconify.design/tabler:terminal-2.svg?color=%230071E3&width=24" height="22" align="absmiddle" alt=""> **用法**

四个命令覆盖整条闭环：

| 命令 | 作用 |
| --- | --- |
| `canaryprobe init` | 生成诱饵集 + 签名清单，打印「往哪注入什么」 |
| `canaryprobe plant` | `init` 的别名，重新种一组新诱饵 |
| `canaryprobe watch` | 武装 DNS + TCP 传感器；触发即告警 + 留痕 |
| `canaryprobe report` | 从审计日志生成签名的证据文件 |

**把诱饵放到 agent 能触达的地方。** `init` 会打印精确指引；最简单的是在 agent 主机的 `/etc/hosts` 里加一行，把诱饵区指向 DNS 传感器：

```bash
echo "127.0.0.1   internal-prod-db-42.corp.local" | sudo tee -a /etc/hosts
export INTERNAL_API_TOKEN=cnp_…       # init 打印的假凭证
canaryprobe watch                     # 武装，等待触发
```

**限定观测时长**（跑固定窗口后自动退出，便于批处理 / CI）：

```bash
canaryprobe watch --duration 60       # 观测 60 秒后停止
```

完整的「让真实 coding agent 对接本地端点、看诱饵被触发」的 10 分钟复现流程见 **[`examples/local-agent-demo.md`](./examples/local-agent-demo.md)**。

## 演示

<img src="https://api.iconify.design/tabler:photo.svg?color=%230071E3&width=24" height="22" align="absmiddle" alt=""> **演示**

![demo](assets/demo.gif)

## 配置

<img src="https://api.iconify.design/tabler:adjustments.svg?color=%230071E3&width=24" height="22" align="absmiddle" alt=""> **配置**

`init` 会写出一个 `deployment.yaml`，三条命令共享它，因此只需配置一次：

| 键 | 类型 | 默认值 | 含义 |
| --- | --- | --- | --- |
| `decoy_zone` | string | `corp.local` | 诱饵主机名所在的权威 DNS 区 |
| `dns_sensor.host` / `.port` | string / int | `127.0.0.1` / `5353` | DNS 传感器 bind（非特权端口，无需 root） |
| `conn_sensor.host` / `.port` | string / int | `127.0.0.1` / `5443` | TCP 连接传感器 bind |
| `decoys_file` | string | `decoys.json` | 传感器加载的诱饵列表 |
| `manifest_file` | string | `decoys.manifest.json` | 签名后的诱饵清单（证据用） |
| `audit_file` | string | `audit.jsonl` | 追加式审计留痕 |

> 每部署一把签名密钥（`.canaryprobe.key`，`0600`）为清单和报告签名；也可用环境变量 `CANARYPROBE_SIGNING_KEY` 注入而不落盘。

## 付费版本

<img src="https://api.iconify.design/tabler:receipt.svg?color=%230071E3&width=24" height="22" align="absmiddle" alt=""> **付费版本**

开源核心（`init` / `watch` / `report`）**永久免费、无功能墙**。付费的是合规买家真正要交付给审计的东西——一个 **on-prem / 等保对齐的审计报告版**：

- 签名、可导出的「运行期未观测到隐蔽外联」证据文件，直接进 等保测评 / 审计流程；
- air-gap 内**多主机诱饵编队**统一管理；
- 部署支持。

`report` 生成的那份证据*就是*合规团队采购的交付物。买家按定义都在 air-gap 内，所以走离线 license-key + 对公，不做托管计费。有意向请提 issue 或邮件联系维护者。

## 路线图

<img src="https://api.iconify.design/tabler:map-2.svg?color=%230071E3&width=24" height="22" align="absmiddle" alt=""> **路线图**

- [x] **m1 · 种诱饵** —— `init` 生成诱饵区 + 假凭证，写签名清单，打印注入指引。
- [x] **m2 · 武装传感器** —— DNS + TCP 传感器并发运行，解析 / 连接触发 `TripEvent` + 红色告警 + JSONL 留痕。
- [x] **m3 · 出具报告** —— `report` 从审计日志生成签名的 clean / TRIPPED 证据文件。
- [ ] 多主机诱饵编队管理（付费版）
- [ ] 等保对齐的可导出审计模板（付费版）
- [ ] 更多凭证 / 诱饵形态（cloud metadata、内部包索引 token 等）

## 许可证

<img src="https://api.iconify.design/tabler:license.svg?color=%230071E3&width=24" height="22" align="absmiddle" alt=""> **许可证**

MIT 许可证，详见 [LICENSE](./LICENSE)。欢迎通过 [issue](https://github.com/SuperMarioYL/canaryprobe/issues) 反馈问题或提交 PR。

## Share this

```
CanaryProbe: a honeytoken tripwire for a closed coding agent you can't read.
Plant a decoy host, and the moment the binary probes it you get a red TRIPPED
alarm + a signed audit line — a checkable event, not a decompile.
https://github.com/SuperMarioYL/canaryprobe
```

<p align="center"><sub><a href="./LICENSE">MIT</a> © 2026 SuperMarioYL</sub></p>
