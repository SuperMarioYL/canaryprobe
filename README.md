[English](README.en.md) | **简体中文**

<picture>
  <source media="(max-width: 640px) and (prefers-color-scheme: dark)" srcset="assets/presentation/hero-mobile-dark.svg">
  <source media="(max-width: 640px)" srcset="assets/presentation/hero-mobile-light.svg">
  <source media="(prefers-color-scheme: dark)" srcset="assets/presentation/hero-dark.svg">
  <img src="assets/presentation/hero-light.svg" width="1000" alt="在本地种下主机名与假凭证诱饵，用 DNS/TCP 传感器记录触发，并生成可验证的报告。">
</picture>

**在本地种下主机名与假凭证诱饵，用 DNS/TCP 传感器记录触发，并生成可验证的报告。**

`v0.9.0` · `Python 3.12+` · [Apache-2.0](LICENSE)

[Website](https://canaryprobe.lei6393.com) · [Demo record](docs/demo-results.json)

## 为什么使用

在无法直接检查 Agent 内部行为的环境里，诱饵提供了一个具体观察点：是否有请求触碰到预先安排的值。CanaryProbe 把触发来源、时间和传感器类型写进本地审计记录，供部署者结合运行场景判断。

## 架构

<picture>
  <source media="(max-width: 640px) and (prefers-color-scheme: dark)" srcset="assets/presentation/architecture-mobile-dark.svg">
  <source media="(max-width: 640px)" srcset="assets/presentation/architecture-mobile-light.svg">
  <source media="(prefers-color-scheme: dark)" srcset="assets/presentation/architecture-dark.svg">
  <img src="assets/presentation/architecture-light.svg" width="1000" alt="init 生成诱饵、部署配置与 HMAC 清单。watch 在一个进程里运行权威 DNS 与 TCP 传感器，触发后向 audit.jsonl 追加事件；report 读取事件和清单生成带 HMAC 的 Markdown，verify 用同一部署密钥重新计算。">
</picture>

init 生成诱饵、部署配置与 HMAC 清单。watch 在一个进程里运行权威 DNS 与 TCP 传感器，触发后向 audit.jsonl 追加事件；report 读取事件和清单生成带 HMAC 的 Markdown，verify 用同一部署密钥重新计算。

源码入口：[canaryprobe/cli.py](canaryprobe/cli.py) · [canaryprobe/config.py](canaryprobe/config.py) · [canaryprobe/sensor_dns.py](canaryprobe/sensor_dns.py) · [canaryprobe/sensor_conn.py](canaryprobe/sensor_conn.py) · [canaryprobe/decoy.py](canaryprobe/decoy.py) · [canaryprobe/report.py](canaryprobe/report.py) · [examples/local-agent-demo.md](examples/local-agent-demo.md)

## 安装

需要 Python 3.12+ 与 uv。演示临时绑定回环 UDP 端口，无需 root，不修改系统 DNS 或 hosts。

```bash
git clone https://github.com/SuperMarioYL/canaryprobe.git
cd canaryprobe
uv venv --python 3.12
uv pip install --python .venv/bin/python -e .
```

## 快速开始

脚本创建临时诱饵，向真实本地 DNS 传感器发送一次查询，再校验报告和清单。没有启动 Coding Agent，也未测试外部网络；生成的主机名、端口与时间会随运行变化。

```bash
.venv/bin/python examples/presentation-demo.py
```

完整输入与执行步骤见上方命令及 [Demo 记录](docs/demo-results.json)。

## 使用

```bash
.venv/bin/canaryprobe init --dir ./deployment
.venv/bin/canaryprobe watch --dir ./deployment --duration 60
.venv/bin/canaryprobe report --dir ./deployment
.venv/bin/canaryprobe verify --dir ./deployment
```
watch 运行期间可在另一终端使用 `simulate-trip --dir ./deployment --sensor dns` 或 `--sensor conn`。`plant` 是 init 的别名；报告可通过 `--output` 改写路径，verify 可用 `--report` 选择报告。

## 实际 Demo

<picture>
  <source media="(max-width: 640px) and (prefers-color-scheme: dark)" srcset="assets/presentation/process-mobile-dark.svg">
  <source media="(max-width: 640px)" srcset="assets/presentation/process-mobile-light.svg">
  <source media="(prefers-color-scheme: dark)" srcset="assets/presentation/process-dark.svg">
  <img src="assets/presentation/process-light.svg" width="1000" alt="脚本创建临时诱饵，向真实本地 DNS 传感器发送一次查询，再校验报告和清单。没有启动 Coding Agent，也未测试外部网络；生成的主机名、端口与时间会随运行变化。">
</picture>

### 触发并验证

DNS 返回回环地址；报告记录 1 个事件，清单与报告签名均验证成功。

```text
$ .venv/bin/python examples/presentation-demo.py
Request: [127.0.0.1:63137] (udp) / 'ci-runner-07-91.corp.local.' (A)
Reply: [127.0.0.1:63137] (udp) / 'ci-runner-07-91.corp.local.' (A) / RRs: A
{
  "dns_answer": "127.0.0.1",
  "verdict": "TRIPPED",
  "events": 1,
  "manifest_verified": true,
  "report_verified": true
}
```

## 能力与接入

<picture>
  <source media="(max-width: 640px) and (prefers-color-scheme: dark)" srcset="assets/presentation/integrations-mobile-dark.svg">
  <source media="(max-width: 640px)" srcset="assets/presentation/integrations-mobile-light.svg">
  <source media="(prefers-color-scheme: dark)" srcset="assets/presentation/integrations-dark.svg">
  <img src="assets/presentation/integrations-light.svg" width="1000" alt="默认 DNS 绑定 127.0.0.1:5353，TCP 绑定 127.0.0.1:5443。必须让实际测试流量到达这些传感器；单独修改 /etc/hosts 不会把 DNS 查询导向 5353。">
</picture>

默认 DNS 绑定 127.0.0.1:5353，TCP 绑定 127.0.0.1:5443。必须让实际测试流量到达这些传感器；单独修改 /etc/hosts 不会把 DNS 查询导向 5353。



## 配置

deployment.yaml 统一管理 `decoy_zone`、`dns_sensor.host/port`、`conn_sensor.host/port`、`decoys_file`、`manifest_file` 与 `audit_file`。默认本地密钥为权限 0600 的 `.canaryprobe.key`，也可设置 `CANARYPROBE_SIGNING_KEY`。保留私有密钥；报告验证需要它。

## 路线图与范围

当前核心为单部署诱饵、用户态传感器、报告与签名验证。多主机编队、更多诱饵类型与特定审计模板属于未来方向；仓库不提供已验收的合规认证。

- CLEAN 只表示读取的日志中没有触发，不能证明系统没有外联。TRIPPED 也不单独证明恶意或成功外泄。
- HMAC 使用共享密钥，属于完整性检查；持有密钥的人可生成报告。日志不是不可修改的存储。

![Terminal recording](assets/demo.gif) · [Recording script](docs/demo.tape)

## 许可证

[Apache-2.0](LICENSE)
