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
	"net/netip"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go/http3"
)

// defaultDialer is used by bare TCP connect probes. It must not use
// TCP_FASTOPEN_CONNECT: that option makes connect(2) return before the
// handshake completes, so every IP — including unreachable ones — would look
// instantly reachable and the race would pick an arbitrary IP.
var defaultDialer = net.Dialer{}

// tfoDialer is used by the HTTP/TLS probes, which write a request right after
// connecting, so TFO actually saves a round trip there.
var tfoDialer = net.Dialer{Control: tcpFastOpenControl}

var baseTLSConfig = &tls.Config{
	InsecureSkipVerify: true,
	// Probes to the same host repeat across queries; resumption skips the
	// asymmetric handshake when the backend still has a valid ticket.
	ClientSessionCache: tls.NewLRUClientSessionCache(64),
}

// bufioReaderPool reuses bufio.Reader objects to avoid per-probe allocation.
var bufioReaderPool = sync.Pool{
	New: func() any { return bufio.NewReaderSize(nil, 4096) },
}

// httpSendCache caches the rendered HTTP request bytes per template+host to
// avoid repeated string replacement on every probe. host must be sanitized.
type httpSendKey struct {
	template string
	host     string
}

var (
	httpSendCacheMu sync.RWMutex
	httpSendCache   = make(map[httpSendKey][]byte, 64)
)

const httpSendCacheMax = 256

func httpSendBytesCached(tpl, host string) []byte {
	k := httpSendKey{template: tpl, host: host}

	httpSendCacheMu.RLock()
	cached, ok := httpSendCache[k]
	httpSendCacheMu.RUnlock()
	if ok {
		return cached
	}

	var result []byte
	if tpl == "" {
		result = []byte("GET / HTTP/1.0\r\n\r\n")
	} else {
		s := strings.ReplaceAll(tpl, "{host}", host)
		s = strings.ReplaceAll(s, "{HOST}", host)
		result = []byte(s)
	}

	httpSendCacheMu.Lock()
	if len(httpSendCache) >= httpSendCacheMax {
		httpSendCache = make(map[httpSendKey][]byte, 64)
	}
	httpSendCache[k] = result
	httpSendCacheMu.Unlock()

	return result
}

// --- HTTP/3 transport pool (per host) ---

const h3TransportTTL = 5 * time.Minute

var (
	h3TransportPool sync.Map // key: host(string) -> *h3TransportEntry
	h3CleanupOnce   sync.Once
	h3CleanupStopCh = make(chan struct{})
)

type h3TransportEntry struct {
	tr      *http3.Transport
	client  *http.Client
	tlsCfg  *tls.Config
	created time.Time
}

func getH3Transport(host string) *h3TransportEntry {
	h3CleanupOnce.Do(startH3Cleanup)

	if v, ok := h3TransportPool.Load(host); ok {
		entry := v.(*h3TransportEntry)
		if time.Since(entry.created) < h3TransportTTL {
			return entry
		}
		h3TransportPool.Delete(host)
		go entry.tr.Close()
	}

	tlsCfg := baseTLSConfig.Clone()
	tlsCfg.ServerName = host
	tr := &http3.Transport{
		TLSClientConfig: tlsCfg,
	}
	entry := &h3TransportEntry{
		tr: tr,
		client: &http.Client{
			Transport: tr,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		tlsCfg:  tlsCfg,
		created: time.Now(),
	}
	actual, _ := h3TransportPool.LoadOrStore(host, entry)
	actualEntry := actual.(*h3TransportEntry)
	if actualEntry != entry {
		tr.Close()
	}
	return actualEntry
}

func startH3Cleanup() {
	go func() {
		ticker := time.NewTicker(h3TransportTTL)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				now := time.Now()
				h3TransportPool.Range(func(key, value any) bool {
					entry := value.(*h3TransportEntry)
					if now.Sub(entry.created) >= h3TransportTTL {
						h3TransportPool.Delete(key)
						entry.tr.Close()
					}
					return true
				})
			case <-h3CleanupStopCh:
				return
			}
		}
	}()
}

// stopH3Cleanup stops the H3 transport cleanup goroutine and closes all
// pooled transports. Called during plugin shutdown.
func stopH3Cleanup() {
	select {
	case <-h3CleanupStopCh:
		// already closed
	default:
		close(h3CleanupStopCh)
	}
	h3TransportPool.Range(func(key, value any) bool {
		entry := value.(*h3TransportEntry)
		entry.tr.Close()
		h3TransportPool.Delete(key)
		return true
	})
}

type prober struct {
	timeout          time.Duration
	parallelChecks   bool
	maxConcurrency   int
	httpSendTpl      string
	httpAliveClasses map[httpAliveClass]struct{}
	pingFn           func(ctx context.Context, ip net.IP) error
}

type ipPicker interface {
	pickBest(ctx context.Context, host string, pref ipPreference, ips []net.IP, checks []checkSpec) (net.IP, bool)
	pickBestBoth(ctx context.Context, host string, ips []net.IP, checks []checkSpec) (bestV4, bestV6 net.IP)
}

func newDefaultProber(timeout time.Duration, parallelChecks bool, httpSend []byte, httpAliveClasses map[httpAliveClass]struct{}) *prober {
	cp := make(map[httpAliveClass]struct{}, len(httpAliveClasses))
	for k := range httpAliveClasses {
		cp[k] = struct{}{}
	}
	return &prober{
		timeout:          timeout,
		parallelChecks:   parallelChecks,
		maxConcurrency:   32,
		httpSendTpl:      string(httpSend),
		httpAliveClasses: cp,
		pingFn:           pingOnce,
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

func ctxLeft(ctx context.Context) string {
	if ctx == nil {
		return "nil"
	}
	dl, ok := ctx.Deadline()
	if !ok {
		return "none"
	}
	left := time.Until(dl)
	if left < 0 {
		left = 0
	}
	return left.String()
}

func errDetails(err error) string {
	if err == nil {
		return "nil"
	}

	timeoutStr := "unknown"
	tempStr := "unknown"
	if ne, ok := err.(net.Error); ok {
		timeoutStr = strconv.FormatBool(ne.Timeout())
		tempStr = strconv.FormatBool(ne.Temporary())
	}

	op := ""
	network := ""
	addr := ""
	var oe *net.OpError
	if errors.As(err, &oe) && oe != nil {
		op = oe.Op
		network = oe.Net
		if oe.Addr != nil {
			addr = oe.Addr.String()
		}
	}

	unwrapped := errors.Unwrap(err)
	unwrappedType := "<nil>"
	if unwrapped != nil {
		unwrappedType = reflect.TypeOf(unwrapped).String()
	}

	return "type=" + reflect.TypeOf(err).String() +
		" timeout=" + timeoutStr +
		" temporary=" + tempStr +
		" op=" + op +
		" net=" + network +
		" addr=" + addr +
		" unwrap=" + unwrappedType
}

func (p *prober) pickBest(ctx context.Context, host string, pref ipPreference, ips []net.IP, checks []checkSpec) (net.IP, bool) {
	if len(ips) == 0 {
		return nil, false
	}

	// WithTimeout (rather than AfterFunc) propagates the deadline, so the
	// per-IP probes can reuse it instead of arming a timer each.
	probeCtx, cancel := context.WithTimeout(ctx, p.timeout)
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

	var sem chan struct{}
	if p.maxConcurrency > 0 && len(ips) > p.maxConcurrency {
		sem = make(chan struct{}, p.maxConcurrency)
	}
	for _, ip := range ips {
		ip := ip
		if sem != nil {
			sem <- struct{}{}
		}
		go func() {
			if sem != nil {
				defer func() { <-sem }()
			}
			_, ok := p.probeIP(probeCtx, ip, host, checks)
			resultCh <- outcome{ip: ip, ok: ok}
		}()
	}

	switch pref {
	case ipPrefV6First:
		var v4Candidate net.IP
		for remaining := len(ips); remaining > 0; remaining-- {
			select {
			case <-probeCtx.Done():
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
			case <-probeCtx.Done():
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
			case <-probeCtx.Done():
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

// pickBestBoth races all IPs concurrently and returns the first successful IPv4
// and first successful IPv6 independently. Failed IPs are simply ignored — the
// caller receives nil for any family that had no success.
func (p *prober) pickBestBoth(ctx context.Context, host string, ips []net.IP, checks []checkSpec) (bestV4, bestV6 net.IP) {
	if len(ips) == 0 {
		return nil, nil
	}

	probeCtx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	type outcome struct {
		ip net.IP
		ok bool
	}
	resultCh := make(chan outcome, len(ips))

	v4Total := 0
	v6Total := 0
	for _, ip := range ips {
		if ip.To4() == nil {
			v6Total++
		} else {
			v4Total++
		}
	}

	var sem chan struct{}
	if p.maxConcurrency > 0 && len(ips) > p.maxConcurrency {
		sem = make(chan struct{}, p.maxConcurrency)
	}
	for _, ip := range ips {
		ip := ip
		if sem != nil {
			sem <- struct{}{}
		}
		go func() {
			if sem != nil {
				defer func() { <-sem }()
			}
			_, ok := p.probeIP(probeCtx, ip, host, checks)
			resultCh <- outcome{ip: ip, ok: ok}
		}()
	}

	v4Remain := v4Total
	v6Remain := v6Total
	for remaining := len(ips); remaining > 0; remaining-- {
		select {
		case <-probeCtx.Done():
			return bestV4, bestV6
		case r := <-resultCh:
			if !r.ok {
				if r.ip.To4() == nil {
					v6Remain--
				} else {
					v4Remain--
				}
				if bestV4 != nil && bestV6 != nil {
					return bestV4, bestV6
				}
				if bestV4 != nil && v6Remain == 0 {
					return bestV4, bestV6
				}
				if bestV6 != nil && v4Remain == 0 {
					return bestV4, bestV6
				}
				continue
			}

			if r.ip.To4() != nil {
				v4Remain--
				if bestV4 == nil {
					bestV4 = r.ip
				}
			} else {
				v6Remain--
				if bestV6 == nil {
					bestV6 = r.ip
				}
			}

			if bestV4 != nil && bestV6 != nil {
				return bestV4, bestV6
			}
			if bestV4 != nil && v6Remain == 0 {
				return bestV4, bestV6
			}
			if bestV6 != nil && v4Remain == 0 {
				return bestV4, bestV6
			}
		}
	}
	return bestV4, bestV6
}

func (p *prober) probeIP(ctx context.Context, ip net.IP, host string, checks []checkSpec) (time.Duration, bool) {
	if len(checks) == 0 {
		return 0, true
	}

	parentCtx := ctx
	if parentCtx == nil {
		parentCtx = context.Background()
	}
	// The caller normally already bounded this batch with a deadline; reuse it
	// so racing N IPs does not arm N timers. The deadline also has to exist,
	// because the HTTP probe relies on it for its socket read deadline.
	var probeCtx context.Context
	var cancel context.CancelFunc
	if _, ok := parentCtx.Deadline(); ok {
		probeCtx, cancel = context.WithCancel(parentCtx)
	} else {
		probeCtx, cancel = context.WithTimeout(parentCtx, p.timeout)
	}
	defer cancel()

	var (
		pingSeen bool
		pingOK   bool
		pingDur  time.Duration
	)
	for _, c := range checks {
		if c.kind == checkPing {
			pingSeen = true
			break
		}
	}
	others := checks
	if pingSeen {
		others = make([]checkSpec, 0, len(checks)-1)
		for _, c := range checks {
			if c.kind != checkPing {
				others = append(others, c)
			}
		}
	}

	if speedcheckDebug {
		speedcheckDebugf("probe ip=%s host=%s ping=%t others=%d parallel=%t timeout=%s", ip.String(), host, pingSeen, len(others), p.parallelChecks, p.timeout)
	}

	if pingSeen && (!p.parallelChecks || len(others) == 0) {
		start := time.Now()
		if err := p.pingFn(probeCtx, ip); err == nil {
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
		ctx2, cancel2 := context.WithCancel(probeCtx)
		defer cancel2()

		resultCh := make(chan probeResult, len(others)+1)
		if pingSeen {
			go func() {
				start := time.Now()
				err := p.pingFn(ctx2, ip)
				d := time.Since(start)
				if speedcheckDebug && shouldLogProbeErr(err) {
					speedcheckDebugf("check host=%s ip=%s kind=%s ok=%t dur=%s left=%s err=%v errDetail=%s", host, ip.String(), checkKindName(checkPing), err == nil, d, ctxLeft(ctx2), err, errDetails(err))
				}
				resultCh <- probeResult{kind: checkPing, d: d, ok: err == nil, err: err}
			}()
		}
		for _, c := range others {
			c := c
			go func() {
				// ctx2 already carries the batch deadline and is cancelled as
				// soon as any check succeeds; no per-check timer is needed.
				switch c.kind {
				case checkTCP:
					start := time.Now()
					err := tcpConnect(ctx2, ip, c.port)
					d := time.Since(start)
					if speedcheckDebug && shouldLogProbeErr(err) {
						speedcheckDebugf("check host=%s ip=%s kind=%s port=%d ok=%t dur=%s left=%s err=%v errDetail=%s", host, ip.String(), checkKindName(c.kind), c.port, err == nil, d, ctxLeft(ctx2), err, errDetails(err))
					}
					resultCh <- probeResult{kind: c.kind, port: c.port, d: d, ok: err == nil, err: err}
				case checkHTTP:
					d, err := p.httpProbe(ctx2, ip, c.port, host)
					if speedcheckDebug && shouldLogProbeErr(err) {
						speedcheckDebugf("check host=%s ip=%s kind=%s port=%d ok=%t dur=%s left=%s err=%v errDetail=%s", host, ip.String(), checkKindName(c.kind), c.port, err == nil, d, ctxLeft(ctx2), err, errDetails(err))
					}
					resultCh <- probeResult{kind: c.kind, port: c.port, d: d, ok: err == nil, err: err}
				default:
					err := errors.New("unknown check kind")
					if speedcheckDebug {
						speedcheckDebugf("check host=%s ip=%s kind=%s ok=%t err=%v", host, ip.String(), checkKindName(c.kind), false, err)
					}
					resultCh <- probeResult{kind: c.kind, ok: false, err: err}
				}
			}()
		}

		remainingTotal := len(others)
		if pingSeen {
			remainingTotal++
		}
		for remaining := remainingTotal; remaining > 0; remaining-- {
			select {
			case <-probeCtx.Done():
				if pingOK {
					return pingDur, true
				}
				return 0, false
			case r := <-resultCh:
				if r.kind == checkPing {
					if r.ok {
						cancel2()
						return r.d, true
					}
					continue
				}
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
		// probeCtx already carries the batch deadline, so the checks can share
		// it instead of allocating a context (and a timer) per check.
		ctxCheck := probeCtx
		for _, c := range others {
			switch c.kind {
			case checkTCP:
				start := time.Now()
				if err := tcpConnect(ctxCheck, ip, c.port); err == nil {
					if speedcheckDebug {
						speedcheckDebugf("check host=%s ip=%s kind=%s port=%d ok=%t dur=%s left=%s err=%v", host, ip.String(), checkKindName(c.kind), c.port, true, time.Since(start), ctxLeft(ctxCheck), nil)
					}
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
					if speedcheckDebug {
						speedcheckDebugf("check host=%s ip=%s kind=%s port=%d ok=%t dur=%s left=%s err=%v errDetail=%s", host, ip.String(), checkKindName(c.kind), c.port, false, time.Since(start), ctxLeft(ctxCheck), err, errDetails(err))
					}
				}
			case checkHTTP:
				d, err := p.httpProbe(ctxCheck, ip, c.port, host)
				if err == nil {
					if speedcheckDebug {
						speedcheckDebugf("check host=%s ip=%s kind=%s port=%d ok=%t dur=%s left=%s err=%v", host, ip.String(), checkKindName(c.kind), c.port, true, d, ctxLeft(ctxCheck), nil)
					}
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
					if speedcheckDebug {
						speedcheckDebugf("check host=%s ip=%s kind=%s port=%d ok=%t dur=%s left=%s err=%v errDetail=%s", host, ip.String(), checkKindName(c.kind), c.port, false, d, ctxLeft(ctxCheck), err, errDetails(err))
					}
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
	conn, err := defaultDialer.DialContext(ctx, "tcp", ipPortString(ip, port))
	if err != nil {
		return err
	}
	setLinger0(conn)
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	_ = conn.Close()
	return nil
}

// ipPortString builds "ip:port" with a single allocation (the string itself)
// instead of ip.String() + strconv.Itoa + JoinHostPort.
func ipPortString(ip net.IP, port uint16) string {
	var buf [64]byte
	b := buf[:0]
	if v4 := ip.To4(); v4 != nil {
		b = netip.AddrFrom4([4]byte{v4[0], v4[1], v4[2], v4[3]}).AppendTo(b)
	} else if addr, ok := netip.AddrFromSlice(ip); ok {
		b = append(b, '[')
		b = addr.AppendTo(b)
		b = append(b, ']')
	} else {
		return ""
	}
	b = append(b, ':')
	b = strconv.AppendUint(b, uint64(port), 10)
	return string(b)
}

func setLinger0(conn net.Conn) {
	if conn == nil {
		return
	}
	tc, ok := conn.(*net.TCPConn)
	if !ok {
		return
	}
	_ = tc.SetLinger(0)
}

func sanitizeHost(host string) string {
	host = strings.ReplaceAll(host, "\r", "")
	host = strings.ReplaceAll(host, "\n", "")
	return host
}

// httpSendBytes is retained for backward compatibility but now delegates
// to the cached version.
func httpSendBytes(httpSend []byte, host string) []byte {
	return httpSendBytesCached(string(httpSend), sanitizeHost(host))
}

func redirectLocationIPFamilyMismatch(location string, probedIP net.IP) bool {
	if location == "" || probedIP == nil {
		return false
	}

	u, err := url.Parse(location)
	if err != nil {
		return false
	}
	host := u.Hostname()
	if host == "" {
		return false
	}
	locIP := net.ParseIP(host)
	if locIP == nil {
		return false
	}
	return (locIP.To4() == nil) != (probedIP.To4() == nil)
}

func readLocationHeader(br *bufio.Reader) (string, error) {
	for i := 0; i < 64; i++ {
		line, err := br.ReadString('\n')
		if err != nil {
			return "", err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			return "", nil
		}

		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(k), "Location") {
			return strings.TrimSpace(v), nil
		}
	}
	return "", nil
}

func (p *prober) httpProbe(ctx context.Context, ip net.IP, port uint16, host string) (time.Duration, error) {
	if ctx == nil {
		ctx = context.Background()
	}
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
	// Data is written immediately after connecting, so TFO saves a round trip.
	rawConn, err := tfoDialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return 0, err
	}
	setLinger0(rawConn)
	defer rawConn.Close()

	conn := rawConn
	if tlsEnabled {
		tlsCfg := baseTLSConfig.Clone()
		tlsCfg.ServerName = host
		// This probe speaks HTTP/1.1 by hand; advertising h2 would make the
		// server expect a binary frame stream and fail the request.
		tlsCfg.NextProtos = []string{"http/1.1"}
		tlsConn := tls.Client(rawConn, tlsCfg)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return 0, err
		}
		conn = tlsConn
	}

	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}

	req := httpSendBytesCached(p.httpSendTpl, host)
	if _, err := conn.Write(req); err != nil {
		return 0, err
	}

	br := bufioReaderPool.Get().(*bufio.Reader)
	br.Reset(conn)
	defer bufioReaderPool.Put(br)
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
	if code/100 == 3 {
		loc, err := readLocationHeader(br)
		if err == nil && redirectLocationIPFamilyMismatch(loc, ip) {
			return 0, fmt.Errorf("http redirect location ip-family mismatch location=%q", loc)
		}
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

	entry := getH3Transport(host)

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return 0, err
	}
	req.Host = host

	resp, err := entry.client.Do(req)
	if err != nil {
		return 0, err
	}
	_ = resp.Body.Close()

	if !p.httpStatusAlive(resp.StatusCode) {
		return 0, fmt.Errorf("http3 status %d not alive", resp.StatusCode)
	}
	if resp.StatusCode/100 == 3 && redirectLocationIPFamilyMismatch(resp.Header.Get("Location"), ip) {
		return 0, fmt.Errorf("http3 redirect location ip-family mismatch location=%q", resp.Header.Get("Location"))
	}
	return time.Since(start), nil
}

func parseHTTPStatus(statusLine string) (int, error) {
	// Status line is "HTTP/1.1 200 OK"; parse it in place to avoid the
	// strings.Fields allocation on every probe.
	i := 0
	for i < len(statusLine) && statusLine[i] != ' ' {
		i++
	}
	for i < len(statusLine) && statusLine[i] == ' ' {
		i++
	}
	code, n := 0, 0
	for i+n < len(statusLine) {
		c := statusLine[i+n]
		if c < '0' || c > '9' {
			break
		}
		code = code*10 + int(c-'0')
		n++
	}
	if n == 0 {
		return 0, fmt.Errorf("invalid http status line")
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
