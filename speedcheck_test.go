package speedcheck

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/test"

	"github.com/miekg/dns"
)

type fakeProber struct {
	ip net.IP
	ok bool
}

func (f fakeProber) pickBest(ctx context.Context, host string, pref ipPreference, ips []net.IP, checks []checkSpec) (net.IP, bool) {
	return f.ip, f.ok
}

type countingProber struct {
	ip    net.IP
	ok    bool
	count int
}

func (c *countingProber) pickBest(ctx context.Context, host string, pref ipPreference, ips []net.IP, checks []checkSpec) (net.IP, bool) {
	c.count++
	return c.ip, c.ok
}

type msgWriter struct {
	test.ResponseWriter
	msg *dns.Msg
}

func (m *msgWriter) WriteMsg(res *dns.Msg) error {
	m.msg = res
	return nil
}

func (m *msgWriter) Write(b []byte) (int, error) { return len(b), nil }

func TestParse(t *testing.T) {
	c := caddy.NewTestController("dns", `
speedcheck {
  speed-check-mode ping,tcp:80,http:443
  speed-ip-mode ipv6,ipv4
  speed-timeout-mode 3s
  check_http_expect_alive http_2xx http_3xx http_5xx
}
`)
	sc, err := parse(c)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !sc.cfg.enabled {
		t.Fatalf("expected enabled")
	}
	if sc.cfg.ipPref != ipPrefV6First {
		t.Fatalf("expected v6 first, got %v", sc.cfg.ipPref)
	}
	if sc.cfg.timeout != 3*time.Second {
		t.Fatalf("expected timeout 3s, got %v", sc.cfg.timeout)
	}
	if sc.cfg.httpAliveClasses == nil {
		t.Fatalf("expected httpAliveClasses set")
	}
	if _, ok := sc.cfg.httpAliveClasses[httpAlive5xx]; !ok {
		t.Fatalf("expected http_5xx enabled")
	}
}

func TestParseSpeedTimeoutMode(t *testing.T) {
	c := caddy.NewTestController("dns", `
speedcheck {
  speed-check-mode ping
  speed-timeout-mode 3s
}
`)
	sc, err := parse(c)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if sc.cfg.timeout != 3*time.Second {
		t.Fatalf("expected timeout 3s, got %v", sc.cfg.timeout)
	}
}

func TestParseDefaultSpeedIPMode(t *testing.T) {
	c := caddy.NewTestController("dns", `
speedcheck {
  speed-check-mode tcp:80
}
`)
	sc, err := parse(c)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if sc.cfg.ipPref != ipPrefV6First {
		t.Fatalf("expected default v6 first, got %v", sc.cfg.ipPref)
	}
}

func TestHTTPStatusAlive(t *testing.T) {
	p := newDefaultProber(1*time.Second, nil, map[httpAliveClass]struct{}{httpAlive5xx: {}})
	if !p.httpStatusAlive(503) {
		t.Fatalf("expected 503 to be alive when http_5xx is configured")
	}
	if p.httpStatusAlive(204) {
		t.Fatalf("expected 204 to be not alive when only http_5xx is configured")
	}

	pAll := newDefaultProber(1*time.Second, nil, nil)
	if !pAll.httpStatusAlive(204) || !pAll.httpStatusAlive(503) {
		t.Fatalf("expected http_all behavior when classes are not configured")
	}
}

func TestHTTPSendTemplateHost(t *testing.T) {
	got := string(httpSendBytes([]byte("HEAD / HTTP/1.1\r\nHost: {host}\r\n\r\n"), "a.example.org"))
	if !strings.Contains(got, "Host: a.example.org\r\n") {
		t.Fatalf("expected host to be substituted, got %q", got)
	}
}

func TestSelectFastestA(t *testing.T) {
	backend := plugin.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = []dns.RR{
			&dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 10}, A: net.ParseIP("1.1.1.1").To4()},
			&dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 10}, A: net.ParseIP("2.2.2.2").To4()},
		}
		_ = w.WriteMsg(m)
		return dns.RcodeSuccess, nil
	})

	sc := &SpeedCheck{
		Next: backend,
		cfg: config{
			enabled: true,
			checks:  []checkSpec{{kind: checkTCP, port: 80}},
			timeout: 1 * time.Second,
		},
		prober: fakeProber{ip: net.ParseIP("2.2.2.2").To4(), ok: true},
	}

	req := new(dns.Msg)
	req.SetQuestion("example.org.", dns.TypeA)

	w := &msgWriter{}
	_, err := sc.ServeDNS(context.Background(), w, req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if w.msg == nil {
		t.Fatalf("expected response")
	}
	if len(w.msg.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(w.msg.Answer))
	}
	a, ok := w.msg.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("expected A record")
	}
	if got := a.A.String(); got != "2.2.2.2" {
		t.Fatalf("expected 2.2.2.2, got %s", got)
	}
}

func TestFallbackWhenAllFailed(t *testing.T) {
	backend := plugin.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = []dns.RR{
			&dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 10}, A: net.ParseIP("1.1.1.1").To4()},
			&dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 10}, A: net.ParseIP("2.2.2.2").To4()},
		}
		_ = w.WriteMsg(m)
		return dns.RcodeSuccess, nil
	})

	sc := &SpeedCheck{
		Next: backend,
		cfg: config{
			enabled: true,
			checks:  []checkSpec{{kind: checkTCP, port: 80}},
			timeout: 1 * time.Second,
		},
		prober: fakeProber{ip: nil, ok: false},
	}

	req := new(dns.Msg)
	req.SetQuestion("example.org.", dns.TypeA)

	w := &msgWriter{}
	_, err := sc.ServeDNS(context.Background(), w, req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if w.msg == nil {
		t.Fatalf("expected response")
	}
	if len(w.msg.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(w.msg.Answer))
	}
	a := w.msg.Answer[0].(*dns.A).A.String()
	if a != "1.1.1.1" && a != "2.2.2.2" {
		t.Fatalf("unexpected fallback ip %s", a)
	}
}

func TestFallbackWhenAllFailedPrefersV4(t *testing.T) {
	backend := plugin.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = []dns.RR{
			&dns.AAAA{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 10}, AAAA: net.ParseIP("2001:db8::1")},
			&dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 10}, A: net.ParseIP("1.1.1.1").To4()},
		}
		_ = w.WriteMsg(m)
		return dns.RcodeSuccess, nil
	})

	sc := &SpeedCheck{
		Next: backend,
		cfg: config{
			enabled: true,
			checks:  []checkSpec{{kind: checkTCP, port: 80}},
			timeout: 1 * time.Second,
		},
		prober: fakeProber{ip: nil, ok: false},
	}

	req := new(dns.Msg)
	req.SetQuestion("example.org.", dns.TypeANY)

	w := &msgWriter{}
	_, err := sc.ServeDNS(context.Background(), w, req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if w.msg == nil {
		t.Fatalf("expected response")
	}
	if len(w.msg.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(w.msg.Answer))
	}
	a, ok := w.msg.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("expected A record fallback, got %T", w.msg.Answer[0])
	}
	if got := a.A.String(); got != "1.1.1.1" {
		t.Fatalf("expected 1.1.1.1, got %s", got)
	}
}

func TestCacheHitSkipsProbing(t *testing.T) {
	backend := plugin.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = []dns.RR{
			&dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 10}, A: net.ParseIP("1.1.1.1").To4()},
			&dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 10}, A: net.ParseIP("2.2.2.2").To4()},
		}
		_ = w.WriteMsg(m)
		return dns.RcodeSuccess, nil
	})

	cp := &countingProber{ip: net.ParseIP("2.2.2.2").To4(), ok: true}
	sc := &SpeedCheck{
		Next: backend,
		cfg: config{
			enabled:  true,
			checks:   []checkSpec{{kind: checkTCP, port: 80}},
			timeout:  1 * time.Second,
			cacheTTL: 1 * time.Second,
		},
		prober: cp,
		cache:  newIPCache(1 * time.Second),
	}

	req := new(dns.Msg)
	req.SetQuestion("example.org.", dns.TypeA)

	w1 := &msgWriter{}
	_, err := sc.ServeDNS(context.Background(), w1, req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	w2 := &msgWriter{}
	_, err = sc.ServeDNS(context.Background(), w2, req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if cp.count != 1 {
		t.Fatalf("expected 1 probe due to cache hit, got %d", cp.count)
	}
	a := w2.msg.Answer[0].(*dns.A).A.String()
	if a != "2.2.2.2" {
		t.Fatalf("expected cached ip 2.2.2.2, got %s", a)
	}
}

func TestCacheExpiryTriggersReprobe(t *testing.T) {
	backend := plugin.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = []dns.RR{
			&dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 10}, A: net.ParseIP("1.1.1.1").To4()},
			&dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 10}, A: net.ParseIP("2.2.2.2").To4()},
		}
		_ = w.WriteMsg(m)
		return dns.RcodeSuccess, nil
	})

	cp := &countingProber{ip: net.ParseIP("2.2.2.2").To4(), ok: true}
	sc := &SpeedCheck{
		Next: backend,
		cfg: config{
			enabled:  true,
			checks:   []checkSpec{{kind: checkTCP, port: 80}},
			timeout:  1 * time.Second,
			cacheTTL: 10 * time.Millisecond,
		},
		prober: cp,
		cache:  newIPCache(10 * time.Millisecond),
	}

	req := new(dns.Msg)
	req.SetQuestion("example.org.", dns.TypeA)

	w1 := &msgWriter{}
	_, err := sc.ServeDNS(context.Background(), w1, req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	time.Sleep(25 * time.Millisecond)
	w2 := &msgWriter{}
	_, err = sc.ServeDNS(context.Background(), w2, req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if cp.count != 2 {
		t.Fatalf("expected 2 probes due to expiry, got %d", cp.count)
	}
}

func TestProbeIPShortCircuitStopsAfterFirstSuccess(t *testing.T) {
	l1, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l1.Close()

	l2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l2.Close()

	tl1 := l1.(*net.TCPListener)
	tl2 := l2.(*net.TCPListener)

	port1 := uint16(tl1.Addr().(*net.TCPAddr).Port)
	port2 := uint16(tl2.Addr().(*net.TCPAddr).Port)

	accept1Done := make(chan struct{})
	go func() {
		_ = tl1.SetDeadline(time.Now().Add(1 * time.Second))
		c, err := tl1.Accept()
		if err == nil {
			_ = c.Close()
		}
		close(accept1Done)
	}()

	p := newDefaultProber(500*time.Millisecond, nil, nil)
	ip := net.ParseIP("127.0.0.1").To4()
	_, ok := p.probeIP(context.Background(), ip, "example.org", []checkSpec{
		{kind: checkTCP, port: port1},
		{kind: checkTCP, port: port2},
	})
	if !ok {
		t.Fatalf("expected ok")
	}
	<-accept1Done

	_ = tl2.SetDeadline(time.Now().Add(50 * time.Millisecond))
	c, err := tl2.Accept()
	if err == nil {
		_ = c.Close()
		t.Fatalf("expected second port not to be probed")
	}
	if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
		t.Fatalf("expected timeout error, got %v", err)
	}
}

func TestProbeIPShortCircuitTriesNextAfterFailure(t *testing.T) {
	failL, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	failPort := uint16(failL.Addr().(*net.TCPAddr).Port)
	_ = failL.Close()

	okL, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer okL.Close()

	okTL := okL.(*net.TCPListener)
	okPort := uint16(okTL.Addr().(*net.TCPAddr).Port)

	acceptDone := make(chan error, 1)
	go func() {
		_ = okTL.SetDeadline(time.Now().Add(1 * time.Second))
		c, err := okTL.Accept()
		if err == nil {
			_ = c.Close()
		}
		acceptDone <- err
	}()

	p := newDefaultProber(500*time.Millisecond, nil, nil)
	ip := net.ParseIP("127.0.0.1").To4()
	_, ok := p.probeIP(context.Background(), ip, "example.org", []checkSpec{
		{kind: checkTCP, port: failPort},
		{kind: checkTCP, port: okPort},
	})
	if !ok {
		t.Fatalf("expected ok")
	}
	if err := <-acceptDone; err != nil {
		t.Fatalf("expected to probe second port, got accept err %v", err)
	}
}
