//go:build linux

package speedcheck

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// --- High-reliability ICMP engine (Linux) ---
// Uses a single blocking raw socket per AF with a dedicated reader goroutine.
// Pending pings are matched by (id, seq) via a dispatch map.
// Bypasses Go epoll entirely — SO_RCVTIMEO on blocking fd.

type icmpReq struct {
	ch      chan time.Duration
	sent    time.Time
	timeout time.Duration
	once    sync.Once
}

func (r *icmpReq) deliver(d time.Duration) {
	r.once.Do(func() { r.ch <- d })
}

func (r *icmpReq) cancel() {
	r.once.Do(func() { close(r.ch) })
}

type icmpEngine struct {
	v4     bool
	fd     int
	mu     sync.Mutex
	pend   map[string]*icmpReq
	closed bool
}

func newICMPEngine(v4 bool) (*icmpEngine, error) {
	proto := 58
	af := syscall.AF_INET6
	label := "ip6"
	if v4 {
		proto = 1
		af = syscall.AF_INET
		label = "ip4"
	}
	fd, err := syscall.Socket(af, syscall.SOCK_RAW, proto)
	if err != nil {
		speedcheckDebugf("icmp engine %s socket error: %v", label, err)
		return nil, err
	}
	tv := syscall.NsecToTimeval(int64(200 * time.Millisecond))
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_SNDTIMEO, &tv)

	e := &icmpEngine{v4: v4, fd: fd, pend: make(map[string]*icmpReq)}
	speedcheckDebugf("icmp engine %s started fd=%d", label, fd)
	go e.readerLoop()
	return e, nil
}

func (e *icmpEngine) close() {
	e.mu.Lock()
	e.closed = true
	for k, r := range e.pend {
		r.cancel()
		delete(e.pend, k)
	}
	e.mu.Unlock()
	syscall.Close(e.fd)
}

func (e *icmpEngine) pendKey(id, seq int) string {
	return strconv.Itoa(id) + ":" + strconv.Itoa(seq)
}

func (e *icmpEngine) register(id, seq int, timeout time.Duration) <-chan time.Duration {
	ch := make(chan time.Duration, 1)
	e.mu.Lock()
	e.pend[e.pendKey(id, seq)] = &icmpReq{ch: ch, sent: time.Now(), timeout: timeout}
	e.mu.Unlock()
	return ch
}

func (e *icmpEngine) deliver(id, seq int) {
	key := e.pendKey(id, seq)
	e.mu.Lock()
	r, ok := e.pend[key]
	if ok {
		delete(e.pend, key)
	}
	e.mu.Unlock()
	if ok {
		r.deliver(time.Since(r.sent))
	}
}

func (e *icmpEngine) cancel(id, seq int) {
	key := e.pendKey(id, seq)
	e.mu.Lock()
	r, ok := e.pend[key]
	if ok {
		delete(e.pend, key)
	}
	e.mu.Unlock()
	if ok {
		r.cancel()
	}
}

func (e *icmpEngine) cleanupExpired() {
	now := time.Now()
	e.mu.Lock()
	for k, r := range e.pend {
		if now.Sub(r.sent) > r.timeout+100*time.Millisecond {
			r.cancel()
			delete(e.pend, k)
		}
	}
	e.mu.Unlock()
}

func (e *icmpEngine) readerLoop() {
	buf := make([]byte, 1500)
	label := "ip6"
	if e.v4 {
		label = "ip4"
	}
	for {
		e.mu.Lock()
		closed := e.closed
		e.mu.Unlock()
		if closed {
			return
		}

		n, _, err := syscall.Recvfrom(e.fd, buf, 0)
		if err != nil {
			if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
				e.cleanupExpired()
				continue
			}
			speedcheckDebugf("icmp reader %s fatal err=%v", label, err)
			return
		}

		replyID, replySeq, ok := e.parseReply(buf, n)
		if ok {
			speedcheckDebugf("icmp reader %s reply id=%d seq=%d n=%d", label, replyID, replySeq, n)
			e.deliver(replyID, replySeq)
		}
	}
}

func (e *icmpEngine) parseReply(buf []byte, n int) (id, seq int, ok bool) {
	if e.v4 {
		if n < 20 {
			return
		}
		ihl := int(buf[0]&0x0f) * 4
		if n < ihl+8 {
			return
		}
		if buf[ihl] != 0 { // not Echo Reply
			return
		}
		id = int(buf[ihl+4])<<8 | int(buf[ihl+5])
		seq = int(buf[ihl+6])<<8 | int(buf[ihl+7])
		return id, seq, true
	}
	// IPv6: no IP header from SOCK_RAW recv
	if n < 8 {
		return
	}
	if buf[0] != 129 { // not Echo Reply
		return
	}
	id = int(buf[4])<<8 | int(buf[5])
	seq = int(buf[6])<<8 | int(buf[7])
	return id, seq, true
}

var (
	defaultV4Engine *icmpEngine
	defaultV6Engine *icmpEngine
	engineOnce      sync.Once
)

func getICMPEngine(v4 bool) *icmpEngine {
	engineOnce.Do(func() {
		defaultV4Engine, _ = newICMPEngine(true)
		defaultV6Engine, _ = newICMPEngine(false)
	})
	if v4 {
		return defaultV4Engine
	}
	return defaultV6Engine
}

var icmpIDSeq atomic.Uint32

func pingOnce(ctx context.Context, ip net.IP) error {
	if ip == nil {
		return errors.New("nil ip")
	}
	v4 := ip.To4() != nil
	e := getICMPEngine(v4)
	if e == nil {
		return errors.New("icmp engine init failed")
	}

	idSeq := icmpIDSeq.Add(1)
	id := int(idSeq & 0xffff)
	seq := int((idSeq >> 16) & 0xffff)

	echoType := byte(128) // ICMPv6
	if v4 {
		echoType = 8 // ICMPv4
	}
	payload := []byte("coredns-speedcheck")
	pkt := make([]byte, 8+len(payload))
	pkt[0] = echoType
	pkt[1] = 0
	pkt[4] = byte(id >> 8)
	pkt[5] = byte(id)
	pkt[6] = byte(seq >> 8)
	pkt[7] = byte(seq)
	copy(pkt[8:], payload)
	csum := icmpChecksum(pkt)
	pkt[2] = byte(csum >> 8)
	pkt[3] = byte(csum)

	var dst syscall.Sockaddr
	if v4 {
		sa := &syscall.SockaddrInet4{}
		copy(sa.Addr[:], ip.To4())
		dst = sa
	} else {
		sa := &syscall.SockaddrInet6{}
		copy(sa.Addr[:], ip.To16())
		dst = sa
	}

	timeout := time.Second
	if dl, ok := ctx.Deadline(); ok {
		if t := time.Until(dl); t > 0 {
			timeout = t
		}
	}

	ch := e.register(id, seq, timeout)
	if err := syscall.Sendto(e.fd, pkt, 0, dst); err != nil {
		e.cancel(id, seq)
		speedcheckDebugf("ping send error ip=%s err=%v", ip, err)
		return fmt.Errorf("icmp send: %w", err)
	}

	select {
	case <-ctx.Done():
		e.cancel(id, seq)
		speedcheckDebugf("ping ctx done ip=%s err=%v", ip, ctx.Err())
		return ctx.Err()
	case d, ok := <-ch:
		if !ok {
			speedcheckDebugf("ping timeout ip=%s id=%d seq=%d", ip, id, seq)
			return errors.New("icmp recv timeout")
		}
		speedcheckDebugf("ping ok ip=%s rtt=%s", ip, d)
		return nil
	}
}

func icmpChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(data[i])<<8 + uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	sum = (sum >> 16) + (sum & 0xffff)
	sum += sum >> 16
	return ^uint16(sum)
}
