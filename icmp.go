package speedcheck

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// --- ICMP engine (all platforms) ---
// Uses golang.org/x/net/icmp with one shared socket per address family.
// A single reader goroutine demultiplexes echo replies by (ID, Seq), so a
// probe costs one send + one channel wait instead of a socket create/close
// pair plus an extra goroutine. Raw sockets still require CAP_NET_RAW.

var icmpIDSeq atomic.Uint32

// icmpEchoData is the constant payload sent in every echo request.
var icmpEchoData = []byte("coredns-speedcheck")

type pingKey struct {
	id  int
	seq int
}

// icmpFamily owns the shared socket for one address family.
type icmpFamily struct {
	isV4 bool

	mu      sync.Mutex
	conn    *icmp.PacketConn
	err     error // sticky error for permanently unusable sockets (e.g. no CAP_NET_RAW)
	waiters map[pingKey]chan struct{}
}

var icmpEngine = [2]icmpFamily{
	{isV4: true},
	{isV4: false},
}

func pingFamily(isV4 bool) *icmpFamily {
	if isV4 {
		return &icmpEngine[0]
	}
	return &icmpEngine[1]
}

func (f *icmpFamily) echoType() icmp.Type {
	if f.isV4 {
		return ipv4.ICMPTypeEcho
	}
	return ipv6.ICMPTypeEchoRequest
}

func (f *icmpFamily) replyType() icmp.Type {
	if f.isV4 {
		return ipv4.ICMPTypeEchoReply
	}
	return ipv6.ICMPTypeEchoReply
}

// socket returns the shared socket, opening it on first use.
func (f *icmpFamily) socket() (*icmp.PacketConn, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.conn != nil {
		return f.conn, nil
	}
	if f.err != nil {
		return nil, f.err
	}

	network := "ip6:ipv6-icmp"
	if f.isV4 {
		network = "ip4:icmp"
	}
	c, err := icmp.ListenPacket(network, "")
	if err != nil {
		// Permission errors never heal; anything else (e.g. EMFILE) may.
		if errors.Is(err, os.ErrPermission) {
			f.err = err
		}
		return nil, err
	}

	if f.waiters == nil {
		f.waiters = make(map[pingKey]chan struct{}, 16)
	}
	f.conn = c
	go f.readLoop(c)
	return c, nil
}

// drop forgets the cached socket after a read error, so the next ping reopens it.
func (f *icmpFamily) drop(c *icmp.PacketConn) {
	f.mu.Lock()
	if f.conn == c {
		f.conn = nil
	}
	f.mu.Unlock()
	_ = c.Close()
}

func (f *icmpFamily) readLoop(c *icmp.PacketConn) {
	defer f.drop(c)

	buf := make([]byte, 1500)
	proto := icmpProtocol(f.isV4)
	want := f.replyType()

	for {
		n, _, err := c.ReadFrom(buf)
		if err != nil {
			return
		}
		rm, err := icmp.ParseMessage(proto, buf[:n])
		if err != nil || rm.Type != want {
			continue
		}
		body, ok := rm.Body.(*icmp.Echo)
		if !ok {
			continue
		}

		k := pingKey{id: body.ID, seq: body.Seq}
		f.mu.Lock()
		ch, ok := f.waiters[k]
		f.mu.Unlock()
		if !ok {
			continue
		}
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

func (f *icmpFamily) register(k pingKey) chan struct{} {
	ch := make(chan struct{}, 1)
	f.mu.Lock()
	if f.waiters == nil {
		f.waiters = make(map[pingKey]chan struct{}, 16)
	}
	f.waiters[k] = ch
	f.mu.Unlock()
	return ch
}

func (f *icmpFamily) unregister(k pingKey) {
	f.mu.Lock()
	delete(f.waiters, k)
	f.mu.Unlock()
}

func pingOnce(ctx context.Context, ip net.IP) error {
	if ip == nil {
		return errors.New("nil ip")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	isV4 := ip.To4() != nil
	f := pingFamily(isV4)

	c, err := f.socket()
	if err != nil {
		return err
	}

	idSeq := icmpIDSeq.Add(1)
	k := pingKey{id: int(idSeq & 0xffff), seq: int((idSeq >> 16) & 0xffff)}
	ch := f.register(k)
	defer f.unregister(k)

	msg := icmp.Message{
		Type: f.echoType(),
		Code: 0,
		Body: &icmp.Echo{
			ID:   k.id,
			Seq:  k.seq,
			Data: icmpEchoData,
		},
	}
	b, err := msg.Marshal(nil)
	if err != nil {
		return err
	}
	if _, err := c.WriteTo(b, &net.IPAddr{IP: ip}); err != nil {
		return err
	}

	select {
	case <-ch:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// closeICMPEngine closes the shared sockets; in-flight pings fail on cancel.
func closeICMPEngine() {
	for i := range icmpEngine {
		f := &icmpEngine[i]
		f.mu.Lock()
		c := f.conn
		f.conn = nil
		f.mu.Unlock()
		if c != nil {
			_ = c.Close()
		}
	}
}

func icmpProtocol(isV4 bool) int {
	if isV4 {
		return 1
	}
	return 58
}
