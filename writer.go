package speedcheck

import (
	"net"

	"github.com/miekg/dns"
)

type captureWriter struct {
	dns.ResponseWriter
	Msg *dns.Msg
}

func newCaptureWriter(w dns.ResponseWriter) *captureWriter {
	return &captureWriter{ResponseWriter: w}
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
