package speedcheck

import (
	"net"
	"sync"

	"github.com/miekg/dns"
)

type captureWriter struct {
	dns.ResponseWriter
	Msg *dns.Msg
}

// captureWriterPool reuses captureWriter objects so capturing the upstream
// answer does not allocate on every query that needs a probe.
var captureWriterPool = sync.Pool{
	New: func() any { return &captureWriter{} },
}

func newCaptureWriter(w dns.ResponseWriter) *captureWriter {
	cw := captureWriterPool.Get().(*captureWriter)
	cw.ResponseWriter = w
	cw.Msg = nil
	return cw
}

// releaseCaptureWriter returns cw to the pool. The captured *dns.Msg must not
// be used afterwards; the RR slices taken from it remain valid.
func releaseCaptureWriter(cw *captureWriter) {
	if cw == nil {
		return
	}
	cw.ResponseWriter = nil
	cw.Msg = nil
	captureWriterPool.Put(cw)
}

func (c *captureWriter) WriteMsg(m *dns.Msg) error {
	c.Msg = m
	return nil
}

func (c *captureWriter) Write(b []byte) (int, error) {
	c.Msg = new(dns.Msg)
	return len(b), c.Msg.Unpack(b)
}

func (c *captureWriter) LocalAddr() net.Addr  { return c.ResponseWriter.LocalAddr() }
func (c *captureWriter) RemoteAddr() net.Addr { return c.ResponseWriter.RemoteAddr() }
func (c *captureWriter) Close() error         { return c.ResponseWriter.Close() }
func (c *captureWriter) TsigStatus() error    { return c.ResponseWriter.TsigStatus() }
func (c *captureWriter) TsigTimersOnly(b bool) {
	c.ResponseWriter.TsigTimersOnly(b)
}
func (c *captureWriter) Hijack() { c.ResponseWriter.Hijack() }
