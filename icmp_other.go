//go:build !linux

package speedcheck

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// --- ICMP engine (macOS / Windows / other) ---
// Uses golang.org/x/net/icmp with per-ping sockets.
// Simpler than the Linux version; no epoll issues on these platforms.

var icmpIDSeq atomic.Uint32

func pingOnce(ctx context.Context, ip net.IP) error {
	if ip == nil {
		return errors.New("nil ip")
	}

	isV4 := ip.To4() != nil
	var network string
	var echoType, replyType icmp.Type
	if isV4 {
		network = "ip4:icmp"
		echoType = ipv4.ICMPTypeEcho
		replyType = ipv4.ICMPTypeEchoReply
	} else {
		network = "ip6:ipv6-icmp"
		echoType = ipv6.ICMPTypeEchoRequest
		replyType = ipv6.ICMPTypeEchoReply
	}

	c, err := icmp.ListenPacket(network, "")
	if err != nil {
		return err
	}
	defer c.Close()

	idSeq := icmpIDSeq.Add(1)
	id := int(idSeq & 0xffff)
	seq := int((idSeq >> 16) & 0xffff)

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

	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetReadDeadline(dl)
	}

	buf := make([]byte, 1500)
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
		rm, err := icmp.ParseMessage(icmpProtocol(isV4), buf[:n])
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

func icmpProtocol(isV4 bool) int {
	if isV4 {
		return 1
	}
	return 58
}
