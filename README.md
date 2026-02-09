# speedcheck

## Name

speedcheck - 对上游返回的多个 IP 做探测并返回最快的一个 IP。

## Description

speedcheck 会对上游返回的多个 A/AAAA 记录做连通性/速度探测，然后把应答收敛为“最快的一个 IP”。

当 `speed-check-mode` 包含 `ping` 时，排序依据使用 ping 延迟；否则使用第一个成功探测项的耗时。

## Syntax

~~~ txt
speedcheck {
    speed-check-mode ping,tcp:80,tcp:443
    speed-timeout-mode 3s
    speed-ip-mode ipv4,ipv6
    check_http_send "HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    check_http_expect_alive http_2xx http_3xx http_4xx
}
~~~

- `speed-check-mode`：探测模式（`none` / `ping` / `tcp:<port>` / `http:<port>`）
- `speed-timeout-mode`：探测超时时间，默认 `2s`
- `speed-ip-mode`：IP 家族优先级（`ipv4,ipv6` / `ipv6,ipv4` / `ipv4` / `ipv6` / 不配置默认 `ipv6,ipv4`）
- `check_http_send`：自定义 HTTP 探测报文；其中 `{host}` / `{HOST}` 会替换为当前 DNS 查询域名
- `check_http_expect_alive`：HTTP 探测可接受的状态码分类（`http_2xx`/`http_3xx`/`http_4xx`/`http_5xx`/`http_all`）

## Examples

最小示例（server 可启动）：

~~~ corefile
. {
    speedcheck {
        speed-check-mode ping,tcp:80,tcp:443
        speed-timeout-mode 3s
        speed-ip-mode ipv6,ipv4
        check_http_send "HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        check_http_expect_alive http_2xx http_3xx http_4xx
    }
    whoami
}
~~~

HTTP 探测（`http:443` 会并发尝试 HTTPS/1.x 与 HTTP/3，取更快的一个）：

~~~ corefile
. {
    speedcheck {
        speed-check-mode ping,http:80,http:443
        speed-timeout-mode 2s
        check_http_expect_alive http_2xx http_3xx
    }
    whoami
}
~~~

## Build

当前仓库已内置 speedcheck（见 [plugin.cfg](file:///opt/coredns/plugin.cfg#L53)），正常编译 CoreDNS 就会包含该模块。

~~~ txt
make
~~~

如果你是把 speedcheck 作为新模块“集成进自己的 CoreDNS 分叉仓库”，按下面步骤：

1) 在 `plugin.cfg` 增加一行（放在你希望的执行顺序位置）：

~~~ txt
speedcheck:speedcheck
~~~

2) 重新生成插件注册代码：

~~~ txt
go generate coredns.go
~~~

3) 编译：

~~~ txt
make
~~~

交叉编译（Linux arm64）：

~~~ txt
make coredns-arm64
~~~
