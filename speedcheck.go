package speedcheck

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"strconv"
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
}

func (s *SpeedCheck) Name() string { return pluginName }

var speedcheckDebug = os.Getenv("SPEEDCHECK_DEBUG") != ""

func speedcheckDebugf(format string, args ...interface{}) {
	if !speedcheckDebug {
		return
	}
	_, _ = fmt.Fprintf(os.Stderr, "speedcheck-debug: "+format+"\n", args...)
}

const maxCacheEntries = 4096

type ipCache struct {
	ttl time.Duration
	mu  sync.RWMutex
	m   map[string]cacheEntry
}

type cacheEntry struct {
	ip        string
	expiresAt time.Time
}

func newIPCache(ttl time.Duration) *ipCache {
	if ttl <= 0 {
		return nil
	}
	return &ipCache{ttl: ttl, m: make(map[string]cacheEntry)}
}

func cacheKey(host string, qtype uint16) string {
	return host + "|" + strconv.Itoa(int(qtype))
}

func (c *ipCache) Get(host string, qtype uint16, now time.Time) (string, bool) {
	if c == nil {
		return "", false
	}
	k := cacheKey(host, qtype)

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
	k := cacheKey(host, qtype)
	c.mu.Lock()
	if len(c.m) >= maxCacheEntries {
		for k, e := range c.m {
			if now.After(e.expiresAt) {
				delete(c.m, k)
			}
		}
		if len(c.m) >= maxCacheEntries {
			c.mu.Unlock()
			return
		}
	}
	c.m[k] = cacheEntry{ip: ip, expiresAt: now.Add(c.ttl)}
	c.mu.Unlock()
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

	speedcheckDebugf("query name=%s qtype=%d parallelChecks=%t parallelIPs=%t ipPref=%d timeout=%s", q.Name, q.Qtype, s.cfg.parallelChecks, s.cfg.parallelIPs, s.cfg.ipPref, s.cfg.timeout)

	cw := newCaptureWriter(w)
	rcode, err := plugin.NextOrFailure(s.Name(), s.Next, ctx, cw, r)
	if cw.Msg == nil {
		speedcheckDebugf("upstream no message name=%s qtype=%d rcode=%d err=%v", q.Name, q.Qtype, rcode, err)
		return rcode, err
	}

	msg := cw.Msg.Copy()
	if msg.Rcode != dns.RcodeSuccess {
		speedcheckDebugf("upstream non-success name=%s qtype=%d rcode=%d", q.Name, q.Qtype, msg.Rcode)
		state := request.Request{W: w, Req: r}
		state.SizeAndDo(msg)
		_ = w.WriteMsg(msg)
		return msg.Rcode, err
	}

	host := strings.TrimSuffix(q.Name, ".")
	override, hasOverride := s.findOverride(strings.ToLower(host))

	checks := s.cfg.checks
	pref := s.cfg.ipPref
	parallelIPs := s.cfg.parallelIPs
	allowOther := false
	if hasOverride {
		if override.enabled {
			checks = override.checks
		} else {
			checks = nil
		}
		pref = override.ipPref
		parallelIPs = false
		allowOther = override.allowOther
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
		state := request.Request{W: w, Req: r}
		state.SizeAndDo(msg)
		_ = w.WriteMsg(msg)
		return msg.Rcode, err
	}

	if hasOverride && (q.Qtype == dns.TypeA || q.Qtype == dns.TypeAAAA) {
		if q.Qtype == dns.TypeAAAA {
			if pref == ipPrefV4First {
				if allowOther {
					if _, ok := s.selectFastestStrictWith(ctx, host, dns.TypeA, s.fetchUpstreamAnswer(w, r, dns.TypeA), checks, ipPrefV4First, false); ok {
						speedcheckDebugf("host override prefer ipv4 (v4 ok), return empty AAAA host=%s", host)
						msg.Answer = s.dropAAAA(msg.Answer)
						state := request.Request{W: w, Req: r}
						state.SizeAndDo(msg)
						_ = w.WriteMsg(msg)
						return msg.Rcode, err
					}
				} else {
					speedcheckDebugf("host override force ipv4, return empty AAAA host=%s", host)
					msg.Answer = s.dropAAAA(msg.Answer)
					state := request.Request{W: w, Req: r}
					state.SizeAndDo(msg)
					_ = w.WriteMsg(msg)
					return msg.Rcode, err
				}
			} else {
				if _, ok := s.selectFastestStrictWith(ctx, host, dns.TypeAAAA, msg.Answer, checks, ipPrefV6First, false); ok {
					selected := s.selectFastestWith(ctx, host, dns.TypeAAAA, msg.Answer, checks, ipPrefV6First, false)
					if selected != nil {
						msg.Answer = selected
					}
					state := request.Request{W: w, Req: r}
					state.SizeAndDo(msg)
					_ = w.WriteMsg(msg)
					return msg.Rcode, err
				}
				if allowOther {
					if _, ok := s.selectFastestStrictWith(ctx, host, dns.TypeA, s.fetchUpstreamAnswer(w, r, dns.TypeA), checks, ipPrefV4First, false); ok {
						speedcheckDebugf("host override prefer ipv6 but v6 failed, use ipv4 fallback host=%s", host)
						msg.Answer = s.dropAAAA(msg.Answer)
						state := request.Request{W: w, Req: r}
						state.SizeAndDo(msg)
						_ = w.WriteMsg(msg)
						return msg.Rcode, err
					}
				}
			}
		} else if q.Qtype == dns.TypeA {
			if pref == ipPrefV6First {
				if allowOther {
					if _, ok := s.selectFastestStrictWith(ctx, host, dns.TypeAAAA, s.fetchUpstreamAnswer(w, r, dns.TypeAAAA), checks, ipPrefV6First, false); ok {
						speedcheckDebugf("host override prefer ipv6 (v6 ok), return empty A host=%s", host)
						msg.Answer = s.dropA(msg.Answer)
						state := request.Request{W: w, Req: r}
						state.SizeAndDo(msg)
						_ = w.WriteMsg(msg)
						return msg.Rcode, err
					}
				} else {
					speedcheckDebugf("host override force ipv6, return empty A host=%s", host)
					msg.Answer = s.dropA(msg.Answer)
					state := request.Request{W: w, Req: r}
					state.SizeAndDo(msg)
					_ = w.WriteMsg(msg)
					return msg.Rcode, err
				}
			} else {
				if _, ok := s.selectFastestStrictWith(ctx, host, dns.TypeA, msg.Answer, checks, ipPrefV4First, false); !ok && allowOther {
					if _, ok2 := s.selectFastestStrictWith(ctx, host, dns.TypeAAAA, s.fetchUpstreamAnswer(w, r, dns.TypeAAAA), checks, ipPrefV6First, false); ok2 {
						speedcheckDebugf("host override prefer ipv4 but v4 failed, use ipv6 fallback host=%s", host)
						msg.Answer = s.dropA(msg.Answer)
						state := request.Request{W: w, Req: r}
						state.SizeAndDo(msg)
						_ = w.WriteMsg(msg)
						return msg.Rcode, err
					}
				}
			}
		}
	}
	if q.Qtype == dns.TypeAAAA && s.cfg.parallelIPs {
		if hasOverride {
			speedcheckDebugf("host override disables aaaa-race host=%s", host)
		} else if ip, ok := s.pickBestAcrossFamilies(ctx, host, msg.Answer, r, w); ok {
			speedcheckDebugf("aaaa-race winner name=%s ip=%s", q.Name, ip.String())
			speedcheckDebugf("aaaa-race winner name=%s ip=%s", q.Name, ip.String())
			if ip.To4() != nil {
				speedcheckDebugf("aaaa-race return empty AAAA name=%s", q.Name)
				msg.Answer = s.dropAAAA(msg.Answer)
			} else {
				selected := s.selectFastest(ctx, host, q.Qtype, msg.Answer)
				if selected != nil {
					msg.Answer = selected
				}
			}
			state := request.Request{W: w, Req: r}
			state.SizeAndDo(msg)
			_ = w.WriteMsg(msg)
			return msg.Rcode, err
		}
	}

	selected := s.selectFastestWith(ctx, host, q.Qtype, msg.Answer, checks, pref, parallelIPs)
	if selected != nil {
		msg.Answer = selected
	}

	state := request.Request{W: w, Req: r}
	state.SizeAndDo(msg)
	_ = w.WriteMsg(msg)
	return msg.Rcode, err
}

func (s *SpeedCheck) selectFastest(ctx context.Context, host string, qtype uint16, answer []dns.RR) []dns.RR {
	return s.selectFastestWith(ctx, host, qtype, answer, s.cfg.checks, s.cfg.ipPref, s.cfg.parallelIPs)
}

func (s *SpeedCheck) fetchUpstreamAnswer(w dns.ResponseWriter, r *dns.Msg, qtype uint16) []dns.RR {
	if r == nil || len(r.Question) == 0 {
		return nil
	}
	req := r.Copy()
	req.Question[0].Qtype = qtype

	cw := newCaptureWriter(w)
	ctx2, cancel := context.WithTimeout(context.Background(), s.cfg.timeout)
	defer cancel()
	rcode, _ := plugin.NextOrFailure(s.Name(), s.Next, ctx2, cw, req)
	if cw.Msg == nil || rcode != dns.RcodeSuccess || cw.Msg.Rcode != dns.RcodeSuccess {
		return nil
	}
	return cw.Msg.Answer
}

func (s *SpeedCheck) selectFastestStrictWith(ctx context.Context, host string, qtype uint16, answer []dns.RR, checks []checkSpec, pref ipPreference, parallelIPs bool) ([]dns.RR, bool) {
	var ips []net.IP
	var rrByIP = make(map[string][]dns.RR)
	var preserved []dns.RR

	for _, rr := range answer {
		switch a := rr.(type) {
		case *dns.A:
			if qtype != dns.TypeA && qtype != dns.TypeANY {
				preserved = append(preserved, rr)
				continue
			}
			ip := a.A
			key := ip.String()
			ips = append(ips, ip)
			rrByIP[key] = append(rrByIP[key], rr)
		case *dns.AAAA:
			if qtype != dns.TypeAAAA && qtype != dns.TypeANY {
				preserved = append(preserved, rr)
				continue
			}
			ip := a.AAAA
			key := ip.String()
			ips = append(ips, ip)
			rrByIP[key] = append(rrByIP[key], rr)
		default:
			preserved = append(preserved, rr)
		}
	}

	if len(ips) == 0 {
		return nil, false
	}

	ctx2, cancel := context.WithTimeout(context.Background(), s.cfg.timeout)
	defer cancel()

	if parallelIPs {
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
	return append(preserved, rrByIP[key]...), true
}

func (s *SpeedCheck) selectFastestWith(ctx context.Context, host string, qtype uint16, answer []dns.RR, checks []checkSpec, pref ipPreference, parallelIPs bool) []dns.RR {
	var ips []net.IP
	var rrByIP = make(map[string][]dns.RR)
	var preserved []dns.RR

	for _, rr := range answer {
		switch a := rr.(type) {
		case *dns.A:
			if qtype != dns.TypeA && qtype != dns.TypeANY {
				preserved = append(preserved, rr)
				continue
			}
			ip := a.A
			key := ip.String()
			ips = append(ips, ip)
			rrByIP[key] = append(rrByIP[key], rr)
		case *dns.AAAA:
			if qtype != dns.TypeAAAA && qtype != dns.TypeANY {
				preserved = append(preserved, rr)
				continue
			}
			ip := a.AAAA
			key := ip.String()
			ips = append(ips, ip)
			rrByIP[key] = append(rrByIP[key], rr)
		default:
			preserved = append(preserved, rr)
		}
	}

	if len(ips) == 0 {
		speedcheckDebugf("no ips host=%s qtype=%d", host, qtype)
		return nil
	}

	if ipStr, ok := s.cache.Get(host, qtype, time.Now()); ok {
		if rrs, ok := rrByIP[ipStr]; ok {
			speedcheckDebugf("cache hit host=%s qtype=%d ip=%s", host, qtype, ipStr)
			return append(preserved, rrs...)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.timeout)
	defer cancel()

	if parallelIPs {
		pref = ipPrefNone
	}
	bestIP, ok := s.prober.pickBest(ctx, host, pref, ips, checks)
	if !ok {
		speedcheckDebugf("pickBest failed host=%s qtype=%d ips=%d", host, qtype, len(ips))
		for _, ip := range ips {
			if ip.To4() != nil {
				key := ip.String()
				speedcheckDebugf("fallback pick first v4 host=%s qtype=%d ip=%s", host, qtype, key)
				return append(preserved, rrByIP[key]...)
			}
		}
		ip := ips[rand.IntN(len(ips))]
		key := ip.String()
		speedcheckDebugf("fallback pick random host=%s qtype=%d ip=%s", host, qtype, key)
		return append(preserved, rrByIP[key]...)
	}

	key := bestIP.String()
	s.cache.Set(host, qtype, key, time.Now())
	speedcheckDebugf("pickBest ok host=%s qtype=%d ip=%s", host, qtype, key)
	return append(preserved, rrByIP[key]...)
}

func (s *SpeedCheck) pickBestAcrossFamilies(ctx context.Context, host string, aaaaAnswer []dns.RR, r *dns.Msg, w dns.ResponseWriter) (net.IP, bool) {
	var ips []net.IP
	for _, rr := range aaaaAnswer {
		if a, ok := rr.(*dns.AAAA); ok {
			ips = append(ips, a.AAAA)
		}
	}

	if len(ips) == 0 {
		speedcheckDebugf("aaaa-race no v6 ips host=%s", host)
		return nil, false
	}

	if r == nil || len(r.Question) == 0 {
		speedcheckDebugf("aaaa-race missing request host=%s", host)
		return nil, false
	}

	reqA := r.Copy()
	reqA.Question[0].Qtype = dns.TypeA

	cw := newCaptureWriter(w)
	ctxA, cancelA := context.WithTimeout(context.Background(), s.cfg.timeout)
	defer cancelA()
	rcode, _ := plugin.NextOrFailure(s.Name(), s.Next, ctxA, cw, reqA)
	if cw.Msg == nil || rcode != dns.RcodeSuccess || cw.Msg.Rcode != dns.RcodeSuccess {
		speedcheckDebugf("aaaa-race upstream A failed host=%s rcode=%d msg=%v", host, rcode, cw.Msg != nil)
		return nil, false
	}

	hasV4 := false
	for _, rr := range cw.Msg.Answer {
		if a, ok := rr.(*dns.A); ok && a.A != nil {
			hasV4 = true
			ips = append(ips, a.A)
		}
	}
	if !hasV4 {
		speedcheckDebugf("aaaa-race no v4 ips host=%s", host)
		return nil, false
	}

	ctx2, cancel := context.WithTimeout(context.Background(), s.cfg.timeout)
	defer cancel()

	speedcheckDebugf("aaaa-race probing host=%s ips=%d", host, len(ips))
	best, ok := s.prober.pickBest(ctx2, host, ipPrefNone, ips, s.cfg.checks)
	if ok {
		return best, true
	}
	for _, ip := range ips {
		if ip.To4() != nil {
			speedcheckDebugf("aaaa-race probe failed, force v4 host=%s ip=%s", host, ip.String())
			return ip, true
		}
	}
	return nil, false
}

func (s *SpeedCheck) dropAAAA(answer []dns.RR) []dns.RR {
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
	out := make([]dns.RR, 0, len(answer))
	for _, rr := range answer {
		if _, ok := rr.(*dns.A); ok {
			continue
		}
		out = append(out, rr)
	}
	return out
}

func (s *SpeedCheck) findOverride(host string) (hostOverride, bool) {
	if ov, ok := s.cfg.hostOverrides[host]; ok {
		return ov, true
	}
	for {
		dot := strings.IndexByte(host, '.')
		if dot < 0 {
			break
		}
		host = host[dot+1:]
		if ov, ok := s.cfg.hostOverrides["*."+host]; ok {
			return ov, true
		}
	}
	return hostOverride{}, false
}
