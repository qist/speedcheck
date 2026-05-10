package speedcheck

import (
	"syscall"
)

func tcpFastOpenControl(network, address string, c syscall.RawConn) error {
	var err error
	controlErr := c.Control(func(fd uintptr) {
		// TCP_FASTOPEN_CONNECT = 30 (Linux 4.11+)
		err = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, 30, 1)
	})
	if controlErr != nil {
		return controlErr
	}
	// ignore error — kernel may not support TFO
	_ = err
	return nil
}
