//go:build !linux

package speedcheck

import "syscall"

func tcpFastOpenControl(network, address string, c syscall.RawConn) error {
	return nil
}
