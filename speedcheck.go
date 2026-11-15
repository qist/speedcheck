package speedcheck

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/request"

	"github.com/miekg/dns"
)

type SpeedCheck struct {
	Next plugin.Handler
	cfg  config

	prober ipPicker
	cache  *ipCache
	probes probeGroup
}

func (s *SpeedCheck) Name() string { return pluginName }

func (s *SpeedCheck) OnShutdown() {
	if s.cache != nil {
		s.cache.Close()
	}
	closeICMPEngine()
	stopH3Cleanup()
}

// probeGroup collapses concurrent probes for the same host/family into a
// single race, so a burst of identical queries does not multiply the number
// of outbound connections. Zero value is ready to use.
type probeGroup struct {
	mu sync.Mutex
	m  map[probeKey]*probeCall
}

// probeKey is a comparable key: no per-query string concatenation.
type probeKey struct {
	host  string
	qtype uint16
	pref  ipPreference
}

type probeCall struct {
	done chan struct{}
	ip   net.IP
	ok   bool
}

func (g *probeGroup) do(ctx context.Context, key probeKey, fn func() (net.IP, bool)) (net.IP, bool) {
	g.mu.Lock()
	if c, ok := g.m[key]; ok {
		g.mu.Unlock()
		select {
		case <-c.done:
			return c.ip, c.ok
		case <-ctx.Done():
			// The caller went away; do not pin it to the shared race.
			return nil, false
		}
	}
	if g.m == nil {
		g.m = make(map[probeKey]*probeCall, 16)
	}
	c := &probeCall{done: make(chan struct{})}
	g.m[key] = c
	g.mu.Unlock()

	// Release waiters even if the probe panics.
	defer func() {
		g.mu.Lock()
		delete(g.m, key)
		g.mu.Unlock()
		close(c.done)
	}()

	c.ip, c.ok = fn()
	return c.ip, c.ok
}

var speedcheckDebug = os.Getenv("SPEEDCHECK_DEBUG") != ""

func speedcheckDebugf(format string, args ...interface{}) {
	if !speedcheckDebug {
		return
	}
	_, _ = fmt.Fprintf(os.Stderr, "speedcheck-debug: "+format+"\n", args...)
}

// cacheKey is a zero-allocation composite key for the IP cache.
type cacheKey struct {
	host  string
	qtype uint16
}

type ipCache struct {
	ttl      time.Duration
	mu       sync.RWMutex
	m        map[cacheKey]cacheEntry
	stopOnce sync.Once
	stopCh   chan struct{}
}

type cacheEntry struct {
	ip        string
	expiresAt time.Time
}

func newIPCache(ttl time.Duration) *ipCache {
	if ttl <= 0 {
		return nil
	}
	c := &ipCache{
		ttl:    ttl,
		m:      make(map[cacheKey]cacheEntry),
		stopCh: make(chan struct{}),
	}
	go c.cleanupLoop()
	return c
}

func (c *ipCache) Get(host string, qtype uint16, now time.Time) (string, bool) {
	if c == nil {
		return "", false
	}
	k := cacheKey{host: host, qtype: qtype}

	c.mu.RLock()
	ent, ok := c.m[k]
	c.mu.RUnlock()
	if !ok {
		return "", false
	}
	if now.After(ent.expiresAt) {
		c.mu.Lock()
		ent2, ok2 := c.m[k]
		if ok2 && now.After(ent2.expiresAt) {
			delete(c.m, k)
		}
		c.mu.Unlock()
		return "", false
	}
	return ent.ip, true
}

func (c *ipCache) Set(host string, qtype uint16, ip string, now time.Time) {
	if c == nil {
		return
	}
	k := cacheKey{host: host, qtype: qtype}
	c.mu.Lock()
	c.m[k] = cacheEntry{ip: ip, expiresAt: now.Add(c.ttl)}
	c.mu.Unlock()
}

func (c *ipCache) Clear() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.m = make(map[cacheKey]cacheEntry)
	c.mu.Unlock()
}

func (c *ipCache) Close() {
	if c == nil {
		return
	}
	c.stopOnce.Do(func() {
		close(c.stopCh)
	})
	c.Clear()
}

func (c *ipCache) cleanupLoop() {
	ticker := time.NewTicker(c.ttl)
	defer ticker.Stop()

	for {
		select {
		case now := <-ticker.C:
			c.cleanupExpired(now)
		case <-c.stopCh:
			return
		}
	}
}

func (c *ipCache) cleanupExpired(now time.Time) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	for k, ent := range c.m {
		if now.After(ent.expiresAt) {
			delete(c.m, k)
		}
	}
}

func (s *SpeedCheck) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	if !s.cfg.enabled {
		return plugin.NextOrFailure(s.Name(), s.Next, ctx, w, r)
	}
	if len(r.Question) == 0 {
		return plugin.NextOrFailure(s.Name(), s.Next, ctx, w, r)
	}

	q := r.Question[0]
	if q.Qtype != dns.TypeA && q.Qtype != dns.TypeAAAA && q.Qtype != dns.TypeANY {
		return plugin.NextOrFailure(s.Name(), s.Next, ctx, w, r)
	}

	speedcheckDebugf("query name=%s qtype=%d parallelChecks=%t ipParallelMode=%d ipPref=%d timeout=%s", q.Name, q.Qtype, s.cfg.parallelChecks, s.cfg.ipParallelMode, s.cfg.ipPref, s.cfg.timeout)

	host := strings.TrimSuffix(q.Name, ".")
	override, hasOverride := s.findOverride(strings.ToLower(host))

	checks := s.cfg.checks
	pref := s.cfg.ipPref
	ipParMode := s.cfg.ipParallelMode
	allowOther := false
	if hasOverride {
		if override.enabled {
			checks = override.checks
		} else {
			checks = nil
		}
		pref = override.ipPref
		ipParMode = ipParallelOff
		allowOther = override.allowOther
	}

	// "winner" mode needs the A answer on top of the AAAA one. Start that
	// upstream query before the main one, so the two overlap instead of the A
	// query costing a full extra round trip after the AAAA answer has arrived.
	var prefetchA *aPrefetch
	if ipParMode == ipParallelWinner && q.Qtype == dns.TypeAAAA {
		prefetchA = s.startPrefetchA(ctx, w, r)
		defer prefetchA.cancel()
	}

	cw := newCaptureWriter(w)
	defer releaseCaptureWriter(cw)
	rcode, err := plugin.NextOrFailure(s.Name(), s.Next, ctx, cw, r)
	if cw.Msg == nil {
		speedcheckDebugf("upstream no message name=%s qtype=%d rcode=%d err=%v", q.Name, q.Qtype, rcode, err)
		return rcode, err
	}

	// Shallow copy: only the header changes below (Answer is replaced with a
	// new slice), the RRs themselves are never mutated, and the next plugin may
	// still hold its own reference to cw.Msg.
	msg := *cw.Msg
	if msg.Rcode != dns.RcodeSuccess {
		speedcheckDebugf("upstream non-success name=%s qtype=%d rcode=%d", q.Name, q.Qtype, msg.Rcode)
		s.writeMsg(w, r, &msg)
		return msg.Rcode, err
	}

	if hasOverride && !override.enabled {
		switch q.Qtype {
		case dns.TypeAAAA:
			if pref == ipPrefV4First {
				speedcheckDebugf("host override none, prefer ipv4, return empty AAAA host=%s", host)
				msg.Answer = s.dropAAAA(msg.Answer)
			}
		case dns.TypeA:
			if pref == ipPrefV6First {
				speedcheckDebugf("host override none, prefer ipv6, return empty A host=%s", host)
				msg.Answer = s.dropA(msg.Answer)
			}
		case dns.TypeANY:
			if pref == ipPrefV4First {
				speedcheckDebugf("host override none, prefer ipv4, drop AAAA host=%s", host)
				msg.Answer = s.dropAAAA(msg.Answer)
			} else if pref == ipPrefV6First {
				speedcheckDebugf("host override none, prefer ipv6, drop A host=%s", host)
				msg.Answer = s.dropA(msg.Answer)
			}
		}
		s.writeMsg(w, r, &msg)
		return msg.Rcode, err
	}

	if hasOverride && (q.Qtype == dns.TypeA || q.Qtype == dns.TypeAAAA) {
		if q.Qtype == dns.TypeAAAA {
			if pref == ipPrefV4First {
				if allowOther {
					if _, ok := s.selectFastestStrictWith(ctx, host, dns.TypeA, s.fetchUpstreamAnswer(ctx, w, r, dns.TypeA), checks, ipPrefV4First, ipParallelOff); ok {
						speedcheckDebugf("host override prefer ipv4 (v4 ok), return empty AAAA host=%s", host)
						msg.Answer = s.dropAAAA(msg.Answer)
						s.writeMsg(w, r, &msg)
						return msg.Rcode, err
					}
				} else {
					speedcheckDebugf("host override force ipv4, return empty AAAA host=%s", host)
					msg.Answer = s.dropAAAA(msg.Answer)
					s.writeMsg(w, r, &msg)
					return msg.Rcode, err
				}
			} else {
				if selected := s.selectFastestWith(ctx, host, dns.TypeAAAA, msg.Answer, checks, ipPrefV6First, ipParallelOff); selected != nil {
					msg.Answer = selected
					s.writeMsg(w, r, &msg)
					return msg.Rcode, err
				}
				if allowOther {
					if _, ok := s.selectFastestStrictWith(ctx, host, dns.TypeA, s.fetchUpstreamAnswer(ctx, w, r, dns.TypeA), checks, ipPrefV4First, ipParallelOff); ok {
						speedcheckDebugf("host override prefer ipv6 but v6 failed, use ipv4 fallback host=%s", host)
						msg.Answer = s.dropAAAA(msg.Answer)
						s.writeMsg(w, r, &msg)
						return msg.Rcode, err
					}
				}
			}
		} else if q.Qtype == dns.TypeA {
			if pref == ipPrefV6First {
				if allowOther {
					if _, ok := s.selectFastestStrictWith(ctx, host, dns.TypeAAAA, s.fetchUpstreamAnswer(ctx, w, r, dns.TypeAAAA), checks, ipPrefV6First, ipParallelOff); ok {
						speedcheckDebugf("host override prefer ipv6 (v6 ok), return empty A host=%s", host)
						msg.Answer = s.dropA(msg.Answer)
						s.writeMsg(w, r, &msg)
						return msg.Rcode, err
					}
				} else {
					speedcheckDebugf("host override force ipv6, return empty A host=%s", host)
					msg.Answer = s.dropA(msg.Answer)
					s.writeMsg(w, r, &msg)
					return msg.Rcode, err
				}
			} else {
				if _, ok := s.selectFastestStrictWith(ctx, host, dns.TypeA, msg.Answer, checks, ipPrefV4First, ipParallelOff); !ok && allowOther {
					if _, ok2 := s.selectFastestStrictWith(ctx, host, dns.TypeAAAA, s.fetchUpstreamAnswer(ctx, w, r, dns.TypeAAAA), checks, ipPrefV6First, ipParallelOff); ok2 {
						speedcheckDebugf("host override prefer ipv4 but v4 failed, use ipv6 fallback host=%s", host)
						msg.Answer = s.dropA(msg.Answer)
						s.writeMsg(w, r, &msg)
						return msg.Rcode, err
					}
				}
			}
		}
	}
	// "winner" mode: cross-family race for AAAA queries (original pickBestAcrossFamilies logic).
	// A queries and "on"/"off" modes race within the requested family only.
	if ipParMode == ipParallelWinner && q.Qtype == dns.TypeAAAA {
		// The A records are only needed when the answer actually carries AAAA
		// candidates, so wait for the prefetch lazily.
		fetchA := func() []dns.RR { return prefetchA.wait(ctx) }
		if ip, ok := s.pickBestAcrossFamilies(ctx, host, msg.Answer, fetchA); ok {
			speedcheckDebugf("winner-race winner host=%s ip=%s", host, ip.String())
			if ip.To4() != nil {
				// v4 won — drop AAAA, return NOERROR with non-AAAA records (CNAME etc).
				speedcheckDebugf("winner-race v4 won, dropAAAA host=%s", host)
				msg.Answer = s.dropAAAA(msg.Answer)
				// The client will follow up with an A query; the winner came from
				// that answer, so it can be served straight from cache.
				s.cache.Set(host, dns.TypeA, ip.String(), time.Now())
			} else {
				// v6 won — the race already picked it, no second probe pass needed.
				if selected := answerForIP(msg.Answer, ip, dns.TypeAAAA); selected != nil {
					s.cache.Set(host, dns.TypeAAAA, ip.String(), time.Now())
					msg.Answer = selected
				}
			}
		}
	} else {
		// "on" or "off": race within the requested family only.
		selected := s.selectFastestWith(ctx, host, q.Qtype, msg.Answer, checks, pref, ipParMode)
		if selected != nil {
			msg.Answer = selected
		}
	}

	s.writeMsg(w, r, &msg)
	return msg.Rcode, err
}

func (s *SpeedCheck) writeMsg(w dns.ResponseWriter, req, msg *dns.Msg) {
	state := request.Request{W: w, Req: req}
	state.SizeAndDo(msg)
	_ = w.WriteMsg(msg)
}

func (s *SpeedCheck) fetchUpstreamAnswer(ctx context.Context, w dns.ResponseWriter, r *dns.Msg, qtype uint16) []dns.RR {
	if r == nil || len(r.Question) == 0 {
		return nil
	}
	req := r.Copy()
	req.Question[0].Qtype = qtype

	cw := newCaptureWriter(w)
	defer releaseCaptureWriter(cw)
	ctx2, cancel := context.WithTimeout(ctx, s.cfg.timeout)
	defer cancel()
	rcode, _ := plugin.NextOrFailure(s.Name(), s.Next, ctx2, cw, req)
	if cw.Msg == nil || rcode != dns.RcodeSuccess || cw.Msg.Rcode != dns.RcodeSuccess {
		return nil
	}
	return cw.Msg.Answer
}

// aPrefetch is an upstream A query started in parallel with the main AAAA
// query. It is only used by "winner" mode, where both families are raced.
type aPrefetch struct {
	ch     chan []dns.RR
	cancel context.CancelFunc
}

func (s *SpeedCheck) startPrefetchA(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) *aPrefetch {
	// Copy before the goroutine starts: the request is read concurrently by the
	// main query, and the copy gives the prefetch its own question to rewrite.
	req := r.Copy()

	p := &aPrefetch{ch: make(chan []dns.RR, 1)}
	ctx2, cancel := context.WithTimeout(ctx, s.cfg.timeout)
	p.cancel = cancel

	go func() {
		defer cancel()
		// Buffered channel: the sender never blocks, even when nobody waits
		// (answer had no AAAA candidates, or the request was cancelled).
		p.ch <- s.fetchUpstreamAnswer(ctx2, w, req, dns.TypeA)
	}()
	return p
}

// wait returns the prefetched A records, or nil if the query failed or the
// caller's context expired first. Safe to call on a nil *aPrefetch.
func (p *aPrefetch) wait(ctx context.Context) []dns.RR {
	if p == nil {
		return nil
	}
	select {
	case ans := <-p.ch:
		return ans
	case <-ctx.Done():
		return nil
	}
}

func (s *SpeedCheck) selectFastestStrictWith(ctx context.Context, host string, qtype uint16, answer []dns.RR, checks []checkSpec, pref ipPreference, ipParMode ipParallelMode) ([]dns.RR, bool) {
	var ips []net.IP
	var cands []addrCand
	var preserved []dns.RR

	for _, rr := range answer {
		switch a := rr.(type) {
		case *dns.A:
			if qtype != dns.TypeA && qtype != dns.TypeANY {
				preserved = append(preserved, rr)
				continue
			}
			ips = append(ips, a.A)
			cands = addCandidate(cands, a.A.String(), rr)
		case *dns.AAAA:
			if qtype != dns.TypeAAAA && qtype != dns.TypeANY {
				preserved = append(preserved, rr)
				continue
			}
			ips = append(ips, a.AAAA)
			cands = addCandidate(cands, a.AAAA.String(), rr)
		default:
			preserved = append(preserved, rr)
		}
	}

	if len(ips) == 0 {
		return nil, false
	}

	ctx2, cancel := context.WithTimeout(ctx, s.cfg.timeout)
	defer cancel()

	if ipParMode != ipParallelOff {
		pref = ipPrefNone
	}
	bestIP, ok := s.prober.pickBest(ctx2, host, pref, ips, checks)
	if !ok {
		speedcheckDebugf("pickBest failed host=%s qtype=%d ips=%d", host, qtype, len(ips))
		return nil, false
	}

	key := bestIP.String()
	s.cache.Set(host, qtype, key, time.Now())
	speedcheckDebugf("pickBest ok host=%s qtype=%d ip=%s", host, qtype, key)
	rrs, _ := candRRs(cands, key)
	return append(preserved, rrs...), true
}

func (s *SpeedCheck) selectFastestWith(ctx context.Context, host string, qtype uint16, answer []dns.RR, checks []checkSpec, pref ipPreference, ipParMode ipParallelMode) []dns.RR {
	var ips []net.IP
	var cands []addrCand
	var preserved []dns.RR

	for _, rr := range answer {
		switch a := rr.(type) {
		case *dns.A:
			if qtype == dns.TypeA || qtype == dns.TypeANY {
				ips = append(ips, a.A)
				cands = addCandidate(cands, a.A.String(), rr)
			}
			// Mismatched A records (for AAAA query) are dropped, not preserved.
		case *dns.AAAA:
			if qtype == dns.TypeAAAA || qtype == dns.TypeANY {
				ips = append(ips, a.AAAA)
				cands = addCandidate(cands, a.AAAA.String(), rr)
			}
			// Mismatched AAAA records (for A query) are dropped, not preserved.
		default:
			preserved = append(preserved, rr)
		}
	}

	if len(ips) == 0 {
		speedcheckDebugf("no ips host=%s qtype=%d", host, qtype)
		return nil
	}

	if ipStr, ok := s.cache.Get(host, qtype, time.Now()); ok {
		if rrs, hit := candRRs(cands, ipStr); hit {
			speedcheckDebugf("cache hit host=%s qtype=%d ip=%s", host, qtype, ipStr)
			return append(preserved, rrs...)
		}
	}

	ctx, cancel := context.WithTimeout(ctx, s.cfg.timeout)
	defer cancel()

	// "on"/"winner": race IPs of the requested family, first success wins.
	// "off": use ipPref family preference.
	if ipParMode != ipParallelOff {
		pref = ipPrefNone
	}

	// Share one race between concurrent queries for the same host/family.
	groupKey := probeKey{host: host, qtype: qtype, pref: pref}
	bestIP, ok := s.probes.do(ctx, groupKey, func() (net.IP, bool) {
		// Detached from the caller's context: the shared race must not be
		// aborted because one of the waiting clients went away.
		return s.prober.pickBest(context.WithoutCancel(ctx), host, pref, ips, checks)
	})
	if ok {
		if bestRRs, hit := candRRs(cands, bestIP.String()); hit {
			key := bestIP.String()
			s.cache.Set(host, qtype, key, time.Now())
			speedcheckDebugf("pickBest ok host=%s qtype=%d ip=%s", host, qtype, key)
			return append(preserved, bestRRs...)
		}
		// The shared race answered with an IP this answer no longer contains
		// (upstream rotated), so re-probe with our own context.
		bestIP, ok = s.prober.pickBest(ctx, host, pref, ips, checks)
		if ok {
			key := bestIP.String()
			s.cache.Set(host, qtype, key, time.Now())
			speedcheckDebugf("pickBest ok host=%s qtype=%d ip=%s", host, qtype, key)
			rrs, _ := candRRs(cands, key)
			return append(preserved, rrs...)
		}
	}

	speedcheckDebugf("pickBest failed host=%s qtype=%d ips=%d", host, qtype, len(ips))
	// Fallback: respect ipPref when choosing a fallback IP.
	// In parallel mode (ipParMode != off), pref is set to ipPrefNone above,
	// so the fallback just picks the first available IP.
	if pref == ipPrefV6First {
		for _, ip := range ips {
			if ip.To4() == nil {
				key := ip.String()
				speedcheckDebugf("fallback pick first v6 host=%s qtype=%d ip=%s", host, qtype, key)
				rrs, _ := candRRs(cands, key)
				return append(preserved, rrs...)
			}
		}
	}
	for _, ip := range ips {
		if ip.To4() != nil {
			key := ip.String()
			speedcheckDebugf("fallback pick first v4 host=%s qtype=%d ip=%s", host, qtype, key)
			rrs, _ := candRRs(cands, key)
			return append(preserved, rrs...)
		}
	}
	ip := ips[rand.IntN(len(ips))]
	key := ip.String()
	speedcheckDebugf("fallback pick random host=%s qtype=%d ip=%s", host, qtype, key)
	rrs, _ := candRRs(cands, key)
	return append(preserved, rrs...)
}

// pickBestAcrossFamilies collects AAAA IPs from the answer, adds the A records
// provided by fetchA, then races all IPs. Returns the winning IP.
// fetchA is only called when the AAAA answer has candidates, so a v6-less
// answer does not wait for the prefetched A query.
func (s *SpeedCheck) pickBestAcrossFamilies(ctx context.Context, host string, aaaaAnswer []dns.RR, fetchA func() []dns.RR) (net.IP, bool) {
	var ips []net.IP
	for _, rr := range aaaaAnswer {
		if a, ok := rr.(*dns.AAAA); ok {
			ips = append(ips, a.AAAA)
		}
	}

	if len(ips) == 0 {
		speedcheckDebugf("winner-race no v6 ips host=%s", host)
		return nil, false
	}

	hasV4 := false
	if fetchA != nil {
		for _, rr := range fetchA() {
			if a, ok := rr.(*dns.A); ok && a.A != nil {
				hasV4 = true
				ips = append(ips, a.A)
			}
		}
	}
	if !hasV4 {
		speedcheckDebugf("winner-race no v4 ips host=%s", host)
		return nil, false
	}

	ctx2, cancel := context.WithTimeout(ctx, s.cfg.timeout)
	defer cancel()

	speedcheckDebugf("winner-race probing host=%s ips=%d", host, len(ips))
	best, ok := s.prober.pickBest(ctx2, host, ipPrefNone, ips, s.cfg.checks)
	if ok {
		return best, true
	}
	// All probes failed — force first v4.
	for _, ip := range ips {
		if ip.To4() != nil {
			speedcheckDebugf("winner-race probe failed, force v4 host=%s ip=%s", host, ip.String())
			return ip, true
		}
	}
	return nil, false
}

// addrCand groups the address records of one IP. A short slice is cheaper
// than a map for the handful of addresses a typical answer carries.
type addrCand struct {
	key string
	rrs []dns.RR
}

func addCandidate(cands []addrCand, key string, rr dns.RR) []addrCand {
	for i := range cands {
		if cands[i].key == key {
			cands[i].rrs = append(cands[i].rrs, rr)
			return cands
		}
	}
	return append(cands, addrCand{key: key, rrs: []dns.RR{rr}})
}

func candRRs(cands []addrCand, key string) ([]dns.RR, bool) {
	for i := range cands {
		if cands[i].key == key {
			return cands[i].rrs, true
		}
	}
	return nil, false
}

func (s *SpeedCheck) dropAAAA(answer []dns.RR) []dns.RR {
	drop := false
	for _, rr := range answer {
		if _, ok := rr.(*dns.AAAA); ok {
			drop = true
			break
		}
	}
	if !drop {
		return answer
	}
	out := make([]dns.RR, 0, len(answer))
	for _, rr := range answer {
		if _, ok := rr.(*dns.AAAA); ok {
			continue
		}
		out = append(out, rr)
	}
	return out
}

func (s *SpeedCheck) dropA(answer []dns.RR) []dns.RR {
	drop := false
	for _, rr := range answer {
		if _, ok := rr.(*dns.A); ok {
			drop = true
			break
		}
	}
	if !drop {
		return answer
	}
	out := make([]dns.RR, 0, len(answer))
	for _, rr := range answer {
		if _, ok := rr.(*dns.A); ok {
			continue
		}
		out = append(out, rr)
	}
	return out
}

// answerForIP keeps the non-address records plus the address records of ip,
// dropping the other candidates of the queried family. Returns nil when ip has
// no record in answer.
func answerForIP(answer []dns.RR, ip net.IP, qtype uint16) []dns.RR {
	out := make([]dns.RR, 0, len(answer))
	matched := false
	for _, rr := range answer {
		switch a := rr.(type) {
		case *dns.A:
			if qtype == dns.TypeA || qtype == dns.TypeANY {
				if a.A.Equal(ip) {
					out = append(out, rr)
					matched = true
				}
				continue
			}
		case *dns.AAAA:
			if qtype == dns.TypeAAAA || qtype == dns.TypeANY {
				if a.AAAA.Equal(ip) {
					out = append(out, rr)
					matched = true
				}
				continue
			}
		default:
			out = append(out, rr)
		}
	}
	if !matched {
		return nil
	}
	return out
}

func (s *SpeedCheck) findOverride(host string) (hostOverride, bool) {
	if ov, ok := s.cfg.hostOverrides[host]; ok {
		return ov, true
	}
	if s.cfg.hasWildcardRules {
		// Wildcard rules are stored without the "*." prefix, so matching only
		// needs to check the host and its parent suffixes; no "full."+host key
		// is built per label.
		if ov, ok := s.cfg.wildcardOverrides[host]; ok {
			return ov, true
		}
		for {
			dot := strings.IndexByte(host, '.')
			if dot < 0 {
				break
			}
			host = host[dot+1:]
			if ov, ok := s.cfg.wildcardOverrides[host]; ok {
				return ov, true
			}
		}
		return hostOverride{}, false
	}

	// Fallback for configs assembled without parse (tests, embedders):
	// wildcard rules sit in hostOverrides under their "*." key.
	for {
		if ov, ok := s.cfg.hostOverrides["*."+host]; ok {
			return ov, true
		}
		dot := strings.IndexByte(host, '.')
		if dot < 0 {
			break
		}
		host = host[dot+1:]
	}
	return hostOverride{}, false
}
