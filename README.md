# speedcheck

## Name

speedcheck - 对上游返回的多个 IP 做探测并返回最快的一个 IP。

## Description

speedcheck 拦截包含 A/AAAA 记录的 DNS 应答，对每个候选 IP 执行连通性探测（ICMP ping / TCP 连接 / HTTP 请求），从中选出最快的一个返回给客户端。

探测流程：

1. 向上游转发请求，获取原始应答
2. 从应答中提取 A/AAAA 记录的 IP 列表
3. 并发探测所有 IP（受并发上限控制，默认最多 8 个）
4. 根据 `speed-ip-mode` 的家族偏好选择最优 IP
5. 将应答收敛为单个最优 IP 返回

当所有探测均失败时，优先回落到 IPv4 地址；若无 IPv4 则随机返回一个 IP。

## Syntax

~~~ txt
speedcheck {
    speed-check-mode ping,tcp:80,tcp:443
    speed-timeout-mode 3s
    speed-check-parallel off
    speed-cache-ttl 30s
    speed-ip-mode ipv4,ipv6
    speed-ip-parallel off
    speed-host-override *.example.com|tcp:443,http:443|ipv4,ipv6
    check_http_send "HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    check_http_expect_alive http_2xx http_3xx http_4xx
}
~~~

### speed-check-mode

探测模式，支持 `none` / `ping` / `tcp:<port>` / `http:<port>`，可用逗号组合多种模式。

- 包含 `ping` 时：先做 ICMP ping；ping 成功则该 IP 视为成功（仍会继续尝试 tcp/http，但 tcp/http 全失败时仍按 ping 成功处理）；ping 失败则继续尝试 tcp/http，任意一个成功即短路
- 仅配置 `ping`：只做 ICMP ping 探测
- 不包含 `ping`：按配置顺序尝试 tcp/http，任意一个成功即短路
- 配置为 `none`：禁用探测（仅在 `speed-host-override` 中有意义）

### speed-timeout-mode

单次探测超时时间，默认 `2s`。

### speed-check-parallel

是否并发执行同一 IP 的 tcp/http 探测（`on` / `off`），默认 `off`。

开启后所有 tcp/http 探测同时发起，任意一个成功即短路返回，适合目标端口响应差异较大的场景。

### speed-cache-ttl

缓存探测结果的时间（按 `域名+查询类型` 缓存），默认 `0`（关闭）。缓存上限为 4096 条，超出时自动清理过期条目。

### speed-ip-mode

IP 家族优先级，默认 `ipv6,ipv6`（优先 IPv6）。

| 值 | 含义 |
|---|---|
| `ipv6,ipv6` | 优先 IPv6，IPv6 全部失败时回落到 IPv4 |
| `ipv4,ipv6` | 优先 IPv4，IPv4 全部失败时回落到 IPv6 |
| `ipv4` | 仅使用 IPv4 |
| `ipv6` | 仅使用 IPv6 |

### speed-ip-parallel

是否并发竞速 v4/v6（`on` / `off`），默认 `off`。

开启后忽略 `speed-ip-mode` 的家族优先级，将所有 A/AAAA 的 IP 合并后并发探测，返回最先成功的 IP。当查询类型为 AAAA 且 IPv4 获胜时，返回空 AAAA（促使客户端回落使用 A 记录）。

### speed-host-override

按域名覆盖探测模式与 IP 家族选择，可配置多条。支持精确匹配和泛域名匹配。

#### 语法

推荐语法（管道分隔，避免逗号歧义）：

~~~ txt
speed-host-override <host>|<check-mode>|<ip-mode>
~~~

兼容语法（逗号或空格分隔，不推荐用于多探测项）：

~~~ txt
speed-host-override <host>,<check-mode>,<ip-mode>
speed-host-override <host> <check-mode> <ip-mode>
~~~

#### 泛域名

使用 `*` 前缀匹配所有子域名，逐级向上查找：

| 配置 | `foo.example.com` | `a.b.example.com` | `example.com` |
|---|---|---|---|
| `*.example.com` | 匹配 | 匹配 | 不匹配 |
| `*.b.example.com` | 不匹配 | 匹配 | 不匹配 |

精确匹配优先于泛域名匹配。

#### ip-mode 详解

| 值 | 行为 |
|---|---|
| `ipv4` / `v4` | 仅保留 A 记录；AAAA 查询返回空（促使客户端回落） |
| `ipv6` / `v6` | 仅保留 AAAA 记录；A 查询返回空 |
| `ipv4,ipv6` | 优先 IPv4，IPv4 失败时允许回落到 IPv6 |
| `ipv6,ipv4` | 优先 IPv6，IPv6 失败时允许回落到 IPv4 |

#### check-mode 为 none 时

不做任何探测，也不收敛多 IP 为单 IP，仅按 `ip-mode` 做 A/AAAA 的保留或清空。适用于强制客户端走指定协议家族的场景。

#### 命中 override 后的行为

- 使用该域名专属的 `check-mode` 与 `ip-mode`
- 禁用 `speed-ip-parallel` 的 v4/v6 竞速

### check_http_send

自定义 HTTP/1.x 探测报文。`{host}` / `{HOST}` 会被替换为当前 DNS 查询域名。默认值：

~~~ txt
GET / HTTP/1.0\r\n\r\n
~~~

### check_http_expect_alive

HTTP 探测可接受的状态码分类，可多选：

- `http_2xx` / `http_3xx` / `http_4xx` / `http_5xx`
- `http_all`：接受所有状态码

默认接受所有状态码。

## Examples

### 基础配置

~~~ corefile
. {
    speedcheck {
        speed-check-mode ping,tcp:80,tcp:443
        speed-timeout-mode 3s
        speed-cache-ttl 30s
        speed-ip-mode ipv6,ipv4
    }
    forward . 8.8.8.8
}
~~~

### HTTP 探测

`http:443` 会并发尝试 HTTPS/1.x 与 HTTP/3，取更快的一个：

~~~ corefile
. {
    speedcheck {
        speed-check-mode ping,http:80,http:443
        speed-timeout-mode 2s
        check_http_expect_alive http_2xx http_3xx
    }
    forward . 8.8.8.8
}
~~~

### 泛域名覆盖

对所有 Google 域名强制 IPv4，对 CDN 域名使用 HTTP 探测：

~~~ corefile
. {
    speedcheck {
        speed-check-mode ping,tcp:443
        speed-timeout-mode 2s
        speed-host-override *.google.com|tcp:443|ipv4
        speed-host-override *.cdn.example.com|http:443|ipv6,ipv4
    }
    forward . 8.8.8.8
}
~~~

### 强制协议家族

对特定域名不做探测，仅强制使用 IPv4：

~~~ corefile
. {
    speedcheck {
        speed-check-mode ping,tcp:443
        speed-host-override legacy.example.org|none|ipv4
    }
    forward . 8.8.8.8
}
~~~

### 并发竞速模式

开启 v4/v6 竞速，返回最快响应的 IP：

~~~ corefile
. {
    speedcheck {
        speed-check-mode tcp:443
        speed-timeout-mode 2s
        speed-ip-parallel on
        speed-check-parallel on
    }
    forward . 8.8.8.8
}
~~~

## Notes

- ICMP ping 需要 `CAP_NET_RAW` 权限或 root 权限；缺少权限时 ping 探测会静默失败，不影响其他探测模式
- `http:443` 探测会并发尝试 HTTPS/1.x 和 HTTP/3（QUIC），取先成功的结果
- 探测连接不复用，每次探测都是新建连接，以准确测量连接建立延迟
- 缓存按 `域名+查询类型` 存储，上限 4096 条；超出时清理过期条目，若仍满则跳过缓存
- 探测并发上限为 8 个 IP；超出时排队等待，防止协程爆炸

## Build

1) 拉取 CoreDNS 源码：

~~~ txt
git clone https://github.com/coredns/coredns.git
cd coredns
~~~

2) 在 `plugin.cfg` 增加一行（建议放到 `cache:cache` 前面）：

~~~ txt
speedcheck:github.com/qist/speedcheck
~~~

3) 拉取 speedcheck 模块源码（两种方式任选其一）：

- 方式 A：Go 自动拉取（推荐）

~~~ txt
go get github.com/qist/speedcheck@latest
~~~

- 方式 B：手动 clone（用于固定版本或离线环境）

~~~ txt
cd coredns
git clone https://github.com/qist/speedcheck.git plugin/speedcheck
~~~

4) 重新生成插件注册代码并编译：

~~~ txt
go generate coredns.go
make
~~~

交叉编译（Linux arm64）：

~~~ txt
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o coredns-linux-arm64
~~~
