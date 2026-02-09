package speedcheck

import (
	"context"
	"math/rand/v2"
	"net"
	"strings"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/request"

	"github.com/miekg/dns"
)

type SpeedCheck struct {
	Next plugin.Handler
	cfg  config

	prober ipPicker
}

func (s *SpeedCheck) Name() string { return pluginName }

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

	ctx, cancel := context.WithTimeout(ctx, s.cfg.timeout)
	defer cancel()

	bestIP, ok := s.prober.pickBest(ctx, host, s.cfg.ipPref, ips, s.cfg.checks)
	if !ok {
		ip := ips[rand.IntN(len(ips))]
		key := ip.String()
		return append(preserved, rrByIP[key]...)
	}

	key := bestIP.String()
	return append(preserved, rrByIP[key]...)
}
