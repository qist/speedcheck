package speedcheck

import (
	"context"
	"math/rand/v2"
	"net"
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

	cw := newCaptureWriter(w)
	rcode, err := plugin.NextOrFailure(s.Name(), s.Next, ctx, cw, r)
	if cw.Msg == nil {
		return rcode, err
	}

	msg := cw.Msg.Copy()
	if msg.Rcode != dns.RcodeSuccess {
		state := request.Request{W: w, Req: r}
		state.SizeAndDo(msg)
		_ = w.WriteMsg(msg)
		return msg.Rcode, err
	}

	host := strings.TrimSuffix(q.Name, ".")
	selected := s.selectFastest(ctx, host, q.Qtype, msg.Answer)
	if selected != nil {
		msg.Answer = selected
	}

	state := request.Request{W: w, Req: r}
	state.SizeAndDo(msg)
	_ = w.WriteMsg(msg)
	return msg.Rcode, err
}

func (s *SpeedCheck) selectFastest(ctx context.Context, host string, qtype uint16, answer []dns.RR) []dns.RR {
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
		return nil
	}

	if ipStr, ok := s.cache.Get(host, qtype, time.Now()); ok {
		if rrs, ok := rrByIP[ipStr]; ok {
			return append(preserved, rrs...)
		}
	}

	ctx, cancel := context.WithTimeout(ctx, s.cfg.timeout)
	defer cancel()

	pref := s.cfg.ipPref
	if s.cfg.parallelIPs {
		pref = ipPrefNone
	}
	bestIP, ok := s.prober.pickBest(ctx, host, pref, ips, s.cfg.checks)
	if !ok {
		for _, ip := range ips {
			if ip.To4() != nil {
				key := ip.String()
				return append(preserved, rrByIP[key]...)
			}
		}
		ip := ips[rand.IntN(len(ips))]
		key := ip.String()
		return append(preserved, rrByIP[key]...)
	}

	key := bestIP.String()
	s.cache.Set(host, qtype, key, time.Now())
	return append(preserved, rrByIP[key]...)
}
