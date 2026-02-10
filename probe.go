package speedcheck

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type prober struct {
	timeout          time.Duration
	parallelChecks   bool
	httpSend         []byte
	httpAliveClasses map[httpAliveClass]struct{}
}

type ipPicker interface {
	pickBest(ctx context.Context, host string, pref ipPreference, ips []net.IP, checks []checkSpec) (net.IP, bool)
}

func newDefaultProber(timeout time.Duration, parallelChecks bool, httpSend []byte, httpAliveClasses map[httpAliveClass]struct{}) *prober {
	cp := make(map[httpAliveClass]struct{}, len(httpAliveClasses))
	for k := range httpAliveClasses {
		cp[k] = struct{}{}
	}
	return &prober{
		timeout:          timeout,
		parallelChecks:   parallelChecks,
		httpSend:         httpSend,
		httpAliveClasses: cp,
	}
}

type probeResult struct {
	kind checkKind
	port uint16
	d    time.Duration
	ok   bool
	err  error
}

func checkKindName(k checkKind) string {
	switch k {
	case checkPing:
		return "ping"
	case checkTCP:
		return "tcp"
	case checkHTTP:
		return "http"
	default:
		return "unknown"
	}
}

func shouldLogProbeErr(err error) bool {
	return err == nil || !errors.Is(err, context.Canceled)
}

func (p *prober) pickBest(ctx context.Context, host string, pref ipPreference, ips []net.IP, checks []checkSpec) (net.IP, bool) {
	if len(ips) == 0 {
		return nil, false
	}

	ctx, cancel := context.WithTimeout(context.Background(), p.timeout)
	defer cancel()

	type outcome struct {
		ip net.IP
		ok bool
	}
	resultCh := make(chan outcome, len(ips))

	v4Remain := 0
	v6Remain := 0
	for _, ip := range ips {
		if ip.To4() == nil {
			v6Remain++
		} else {
			v4Remain++
		}
	}

	for _, ip := range ips {
		ip := ip
		go func() {
			_, ok := p.probeIP(ctx, ip, host, checks)
			resultCh <- outcome{ip: ip, ok: ok}
		}()
	}

	switch pref {
	case ipPrefV6First:
		var v4Candidate net.IP
		for remaining := len(ips); remaining > 0; remaining-- {
			select {
			case <-ctx.Done():
				return nil, false
			case r := <-resultCh:
				if r.ip.To4() == nil {
					v6Remain--
					if r.ok {
						cancel()
						return r.ip, true
					}
					if v6Remain == 0 && v4Candidate != nil {
						cancel()
						return v4Candidate, true
					}
					continue
				}

				v4Remain--
				if r.ok && v4Candidate == nil {
					v4Candidate = r.ip
					if v6Remain == 0 {
						cancel()
						return v4Candidate, true
					}
				}
			}
		}
	case ipPrefV4First:
		var v6Candidate net.IP
		for remaining := len(ips); remaining > 0; remaining-- {
			select {
			case <-ctx.Done():
				return nil, false
			case r := <-resultCh:
				if r.ip.To4() != nil {
					v4Remain--
					if r.ok {
						cancel()
						return r.ip, true
					}
					if v4Remain == 0 && v6Candidate != nil {
						cancel()
						return v6Candidate, true
					}
					continue
				}

				v6Remain--
				if r.ok && v6Candidate == nil {
					v6Candidate = r.ip
					if v4Remain == 0 {
						cancel()
						return v6Candidate, true
					}
				}
			}
		}
	default:
		for remaining := len(ips); remaining > 0; remaining-- {
			select {
			case <-ctx.Done():
				return nil, false
			case r := <-resultCh:
				if r.ok {
					cancel()
					return r.ip, true
				}
			}
		}
	}
	return nil, false
}

func (p *prober) probeIP(ctx context.Context, ip net.IP, host string, checks []checkSpec) (time.Duration, bool) {
	if len(checks) == 0 {
		return 0, true
	}

	baseCtx := ctx
	if baseCtx == nil {
		baseCtx = context.Background()
	}
	ctx, cancel := context.WithTimeout(baseCtx, p.timeout)
	defer cancel()

	var (
		pingSeen bool
		pingOK   bool
		pingDur  time.Duration
		others   []checkSpec
	)
	for _, c := range checks {
		if c.kind == checkPing {
			pingSeen = true
			continue
		}
		others = append(others, c)
	}

	if pingSeen {
		start := time.Now()
		if err := pingOnce(ctx, ip); err == nil {
			pingOK = true
			pingDur = time.Since(start)
		}
	}

	if len(others) == 0 {
		if !pingSeen {
			return 0, true
		}
		if pingOK {
			return pingDur, true
		}
		return 0, false
	}

	if p.parallelChecks {
		ctx2, cancel2 := context.WithCancel(ctx)
		defer cancel2()

		resultCh := make(chan probeResult, len(others))
		for _, c := range others {
			c := c
			go func() {
				switch c.kind {
				case checkTCP:
					start := time.Now()
					err := tcpConnect(ctx2, ip, c.port)
					d := time.Since(start)
					if shouldLogProbeErr(err) {
						speedcheckDebugf("check host=%s ip=%s kind=%s port=%d ok=%t dur=%s err=%v", host, ip.String(), checkKindName(c.kind), c.port, err == nil, d, err)
					}
					resultCh <- probeResult{kind: c.kind, port: c.port, d: d, ok: err == nil, err: err}
				case checkHTTP:
					d, err := p.httpProbe(ctx2, ip, c.port, host)
					if shouldLogProbeErr(err) {
						speedcheckDebugf("check host=%s ip=%s kind=%s port=%d ok=%t dur=%s err=%v", host, ip.String(), checkKindName(c.kind), c.port, err == nil, d, err)
					}
					resultCh <- probeResult{kind: c.kind, port: c.port, d: d, ok: err == nil, err: err}
				default:
					err := errors.New("unknown check kind")
					speedcheckDebugf("check host=%s ip=%s kind=%s ok=%t err=%v", host, ip.String(), checkKindName(c.kind), false, err)
					resultCh <- probeResult{kind: c.kind, ok: false, err: err}
				}
			}()
		}

		for remaining := len(others); remaining > 0; remaining-- {
			select {
			case <-ctx.Done():
				if pingOK {
					return pingDur, true
				}
				return 0, false
			case r := <-resultCh:
				if r.ok {
					cancel2()
					if pingOK {
						return pingDur, true
					}
					return r.d, true
				}
			}
		}
	} else {
		for _, c := range others {
			switch c.kind {
			case checkTCP:
				start := time.Now()
				if err := tcpConnect(ctx, ip, c.port); err == nil {
					speedcheckDebugf("check host=%s ip=%s kind=%s port=%d ok=%t dur=%s err=%v", host, ip.String(), checkKindName(c.kind), c.port, true, time.Since(start), nil)
					if pingOK {
						return pingDur, true
					}
					return time.Since(start), true
				} else if errors.Is(err, context.Canceled) {
					if pingOK {
						return pingDur, true
					}
					return 0, false
				} else {
					speedcheckDebugf("check host=%s ip=%s kind=%s port=%d ok=%t dur=%s err=%v", host, ip.String(), checkKindName(c.kind), c.port, false, time.Since(start), err)
				}
			case checkHTTP:
				d, err := p.httpProbe(ctx, ip, c.port, host)
				if err == nil {
					speedcheckDebugf("check host=%s ip=%s kind=%s port=%d ok=%t dur=%s err=%v", host, ip.String(), checkKindName(c.kind), c.port, true, d, nil)
					if pingOK {
						return pingDur, true
					}
					return d, true
				} else if errors.Is(err, context.Canceled) {
					if pingOK {
						return pingDur, true
					}
					return 0, false
				} else {
					speedcheckDebugf("check host=%s ip=%s kind=%s port=%d ok=%t dur=%s err=%v", host, ip.String(), checkKindName(c.kind), c.port, false, d, err)
				}
			default:
				return 0, false
			}
		}
	}

	if pingOK {
		return pingDur, true
	}
	return 0, false
}

func tcpConnect(ctx context.Context, ip net.IP, port uint16) error {
	d := &net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(int(port))))
	if err != nil {
		return err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	_ = conn.Close()
	return nil
}

func pingOnce(ctx context.Context, ip net.IP) error {
	if ip == nil {
		return errors.New("nil ip")
	}

	if ip4 := ip.To4(); ip4 != nil {
		return pingICMP(ctx, "ip4:icmp", ip4, ipv4.ICMPTypeEcho, ipv4.ICMPTypeEchoReply)
	}
	return pingICMP(ctx, "ip6:ipv6-icmp", ip, ipv6.ICMPTypeEchoRequest, ipv6.ICMPTypeEchoReply)
}

func pingICMP(ctx context.Context, network string, ip net.IP, echoType, replyType icmp.Type) error {
	c, err := icmp.ListenPacket(network, "")
	if err != nil {
		return err
	}
	defer c.Close()

	id := int(time.Now().UnixNano() & 0xffff)
	seq := 1
	msg := icmp.Message{
		Type: echoType,
		Code: 0,
		Body: &icmp.Echo{
			ID:   id,
			Seq:  seq,
			Data: []byte("coredns-speedcheck"),
		},
	}
	b, err := msg.Marshal(nil)
	if err != nil {
		return err
	}

	dst := &net.IPAddr{IP: ip}
	if _, err := c.WriteTo(b, dst); err != nil {
		return err
	}

	buf := make([]byte, 1500)
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetReadDeadline(dl)
	}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = c.SetReadDeadline(time.Now())
		case <-done:
		}
	}()
	defer close(done)
	for {
		n, peer, err := c.ReadFrom(buf)
		if err != nil {
			return err
		}
		_ = peer
		rm, err := icmp.ParseMessage(icmpProtocol(network), buf[:n])
		if err != nil {
			continue
		}
		if rm.Type != replyType {
			continue
		}
		body, ok := rm.Body.(*icmp.Echo)
		if !ok {
			continue
		}
		if body.ID != id || body.Seq != seq {
			continue
		}
		return nil
	}
}

func icmpProtocol(network string) int {
	if strings.HasPrefix(network, "ip4:") {
		return 1
	}
	return 58
}

func sanitizeHost(host string) string {
	host = strings.ReplaceAll(host, "\r", "")
	host = strings.ReplaceAll(host, "\n", "")
	return host
}

func httpSendBytes(httpSend []byte, host string) []byte {
	host = sanitizeHost(host)
	if len(httpSend) == 0 {
		return []byte("GET / HTTP/1.0\r\n\r\n")
	}
	s := strings.ReplaceAll(string(httpSend), "{host}", host)
	s = strings.ReplaceAll(s, "{HOST}", host)
	return []byte(s)
}

func (p *prober) httpProbe(ctx context.Context, ip net.IP, port uint16, host string) (time.Duration, error) {
	baseCtx := ctx
	if baseCtx == nil {
		baseCtx = context.Background()
	}
	ctx, cancel := context.WithTimeout(baseCtx, p.timeout)
	defer cancel()
	if port == 443 {
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()

		ch := make(chan probeResult, 2)
		go func() {
			d, err := p.https1Probe(ctx, ip, port, host)
			ch <- probeResult{d: d, ok: err == nil, err: err}
		}()
		go func() {
			d, err := p.http3Probe(ctx, ip, port, host)
			ch <- probeResult{d: d, ok: err == nil, err: err}
		}()

		var firstErr error
		for i := 0; i < 2; i++ {
			select {
			case <-ctx.Done():
				return 0, ctx.Err()
			case r := <-ch:
				if r.ok {
					cancel()
					return r.d, nil
				}
				if firstErr == nil {
					firstErr = r.err
				}
			}
		}
		if firstErr == nil {
			firstErr = errors.New("http probe failed")
		}
		return 0, firstErr
	}
	return p.http1Probe(ctx, ip, port, host, false)
}

func (p *prober) https1Probe(ctx context.Context, ip net.IP, port uint16, host string) (time.Duration, error) {
	return p.http1Probe(ctx, ip, port, host, true)
}

func (p *prober) http1Probe(ctx context.Context, ip net.IP, port uint16, host string, tlsEnabled bool) (time.Duration, error) {
	start := time.Now()
	host = sanitizeHost(host)
	addr := net.JoinHostPort(ip.String(), strconv.Itoa(int(port)))
	d := &net.Dialer{}
	rawConn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return 0, err
	}
	defer rawConn.Close()

	conn := rawConn
	if tlsEnabled {
		tlsConn := tls.Client(rawConn, &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         host,
			NextProtos:         []string{"h2", "http/1.1"},
		})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return 0, err
		}
		conn = tlsConn
	}

	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}

	req := httpSendBytes(p.httpSend, host)
	if _, err := conn.Write(req); err != nil {
		return 0, err
	}

	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil {
		if errors.Is(err, io.EOF) && line == "" {
			return 0, err
		}
	}
	code, err := parseHTTPStatus(line)
	if err != nil {
		return 0, err
	}
	if !p.httpStatusAlive(code) {
		return 0, fmt.Errorf("http status %d not alive", code)
	}
	return time.Since(start), nil
}

func (p *prober) http3Probe(ctx context.Context, ip net.IP, port uint16, host string) (time.Duration, error) {
	start := time.Now()
	host = sanitizeHost(host)

	authority := net.JoinHostPort(ip.String(), strconv.Itoa(int(port)))
	if ip.To4() == nil {
		authority = "[" + ip.String() + "]:" + strconv.Itoa(int(port))
	}
	url := "https://" + authority + "/"

	tr := &http3.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         host,
		},
	}
	defer tr.Close()

	client := &http.Client{
		Transport: tr,
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return 0, err
	}
	req.Host = host

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	_ = resp.Body.Close()

	if !p.httpStatusAlive(resp.StatusCode) {
		return 0, fmt.Errorf("http3 status %d not alive", resp.StatusCode)
	}
	return time.Since(start), nil
}

func parseHTTPStatus(statusLine string) (int, error) {
	parts := strings.Fields(statusLine)
	if len(parts) < 2 {
		return 0, fmt.Errorf("invalid http status line")
	}
	code, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, err
	}
	return code, nil
}

func (p *prober) httpStatusAlive(code int) bool {
	if code < 100 || code > 999 {
		return false
	}
	if p.httpAliveClasses == nil || len(p.httpAliveClasses) == 0 {
		return true
	}
	class := httpAliveClass(code / 100)
	_, ok := p.httpAliveClasses[class]
	return ok
}
