package scanner

import (
	"fmt"
	"net"
)

func GetFreePort() (uint16, error) {
	l, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		return 0, fmt.Errorf("error: open tcp socket: %w", err)
	}

	defer func() {
		if err := l.Close(); err != nil {
			panic(err)
		}
	}()

	addr, ok := l.Addr().(*net.TCPAddr)
	if !ok {
		panic("must not happen")
	}

	return uint16(addr.Port), nil
}
