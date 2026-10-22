# pcaplens — 让 LLM 读抓包的方式

> **先给地图，再给证据。全程不需要 tshark。**

[英文说明](README.md) · [CI](https://github.com/xuange-hu/pcaplens/actions/workflows/ci.yml)

抓包分析的消费者其实只有两类：**正在排查事件的人**，和**必须把答案塞进上下文窗口的 AI Agent**。
pcaplens 就是照着这两类写的。

核心**只用标准库**：不需要 Wireshark、tshark、libpcap、Npcap，也不需要编译器。
在一台没有管理员权限、没有网络共享的 Windows 上 `pip install pcaplens` 就能跑。

## 为什么要重做一个

现在主流的「让 LLM 读 pcap」方案基本都是外层套一层 `tshark`。这是**两个问题披着一件外套**：

1. **不可移植。** tshark 是约 100 MB 的安装包 + 一个 PATH 环境变量。在 Windows 上，
   大多数读者到这一步就放弃了。
2. **会撑爆上下文。** 对 10 MB 抓包执行 `tshark -V` 会产出几十 MB 文本。喂给 Agent
   要么直接超限，要么把别的重要信息全挤出去。

所以 pcaplens 不做全量转储，而是**先给地图，再让你按需下钻**：

```
summary       约 30 行：抓包的形状 + 值得看的东西
conversations 每条流一行，按流量排序，带重传/RST 标记
packet N      完整解析单个帧，带字节偏移和十六进制转储
```

## 快速开始

```bash
pip install pcaplens

pcaplens demo traffic.pcap           # 手上没有抓包？先合成一份
pcaplens summary traffic.pcap
pcaplens flows traffic.pcap
pcaplens packet traffic.pcap 10
pcaplens search traffic.pcap --text example.com
```

`pcaplens demo` 会写出一份真实的 pcap，内含 TCP 三次握手、DNS、HTTP 和 TLS
ClientHello —— 空目录里一条命令就能摸到全部功能。

## 输出长什么样

```
$ pcaplens summary traffic.pcap
packets     : 12   bytes: 1.1KB   duration: 2.00s   (6.0 pkt/s)

protocols (packets, bytes):
protocol  packets  bytes
--------  -------  -----
tcp       6        324B
http      3        442B
dns       2        158B
tls       1        152B

worth a look:
  - 10.0.0.2:52344 <-> 93.184.216.34:80: 1 retransmitted segment(s) (evidence: packet 3)
  - 10.0.0.2:52345 <-> 93.184.216.34:443: 1 SYN sent, no SYN/ACK seen (evidence: packet 9)
```

每条结论都**带上支撑它的报文号**，所以你可以直接打开那一帧核对，而不是盲信摘要：

```
$ pcaplens packet traffic.pcap 10
packet 10  152B  2.010000
  link      : ethernet (file offset 0x3d8)
  summary   : TLS ClientHello SNI=www.example.com TLS1.2

  layers (offset, length):
    ethernet           @0     len=14    ethertype=0x800
    ipv4               @14    len=20    src=10.0.0.2, dst=93.184.216.34, ttl=64, proto=tcp
    tcp                @34    len=20    src_port=52345, dst_port=443, flags=PSH,ACK
    tls-handshake      @54    len=98

  TLS client_hello version=TLS1.2
    SNI: www.example.com
    suites: 0x1301, 0x1302, 0xc02f
```

## 交给 AI Agent 驱动

```bash
pip install "pcaplens[mcp]"
```

```json
{
  "mcpServers": {
    "pcaplens": {
      "command": "pcaplens",
      "args": ["mcp"]
    }
  }
}
```

共 9 个工具：`pcap_summary`、`pcap_conversations`、`pcap_talkers`、
`pcap_protocols`、`pcap_packet`、`pcap_search`、`pcap_dns`、`pcap_http`、`pcap_tls`。

每个工具都遵守和 CLI 一样的三条纪律：**不做全量转储**；列表一律设上限并声明丢了多少；
每条结论都带可复核的报文号。**无法核实的结论，模型一定会编**，而编出来的抓包分析比不做分析更糟。

不开服务就能看到 Agent 能拿到什么：

```bash
pcaplens mcp --check
```

## 解析能力

| 层次 | 覆盖范围 |
|---|---|
| 文件 | 经典 pcap（微秒/纳秒、大端/小端）与 **pcapng**（SHB/IDB/EPB/SPB/PB，未知块按长度跳过） |
| 链路 | Ethernet、802.1Q/QinQ VLAN、Linux cooked v1/v2、raw IP |
| 网络 | IPv4（识别选项、标记分片）、IPv6（扩展头链、RFC 5952 文本形式）、ARP |
| 传输 | TCP（标志位、seq/ack、数据偏移）、UDP、ICMP/ICMPv6 |
| 应用 | DNS（压缩名、问题与应答）、HTTP/1.x 请求与响应、TLS ClientHello/ServerHello（SNI、套件、ALPN） |

解析刻意保守：解析不出来的字段会变成一条**说明**（如「IPv4 分片：其下端口可能不存在」），
而不是编一个看起来合理的猜测。

## 与 tshark 方案的对比

| | 基于 tshark 的 MCP 服务 | pcaplens |
|---|---|---|
| 需要外部二进制 | 是（Wireshark/tshark，约 100 MB） | **否** |
| 无管理员权限的 Windows 可用 | 通常不行 | **可以** |
| 输出形态 | 全量文本转储 | **摘要 + 定向下钻** |
| 上下文预算 | 调用方自己负责 | **列表设上限，截断会声明** |
| 结论是否可复核 | 否 | **报文号 + 字节偏移** |
| 核心依赖 | 数个 | **零** |

## 从源码安装

```bash
git clone https://github.com/xuange-hu/pcaplens && cd pcaplens
pip install -e ".[mcp]"
PYTHONPATH=src pytest -q        # 62 个测试
PYTHONPATH=src python -m pcaplens.cli demo demo.pcap
```

## 已知边界

写清楚，因为猜的代价更高：

* **不做 TCP 重组** —— HTTP 按段解析，跨段的大响应会显示为 "TCP" 而非 "HTTP"。
* **不做 IP 分片重组**；分片只做标记，不拼接。
* TLS 只取元数据（SNI、版本、套件）。加密流量不解密，也不会去解密。
* 启发式只是提示。`unresolved_handshake` 的含义是「**这份抓包里**没看到 SYN/ACK」，
  并不等于「对端主机挂了」。

## 许可

MIT —— 见 [LICENSE](LICENSE)。`demo` 里的流量由 `synth.py` 在本地合成，
不分发任何第三方抓包文件。
