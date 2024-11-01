package ping

import (
	"fmt"
	"net"
	"strings"
)

func IPStringToBytes(ip string) (net.IP, error) {
	if len(strings.Split(ip, ".")) != 4 {
		return nil, ErrInvalidIP
	}

	ipAddr, err := net.ResolveIPAddr("ip", ip)
	if err != nil {
		return nil, fmt.Errorf("error: resolve ip %s: %w", ip, err)
	}

	return ipAddr.IP, nil
}
