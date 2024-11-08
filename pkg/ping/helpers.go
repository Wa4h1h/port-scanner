package ping

import (
	"fmt"
	"net"
	"strings"
)

func IPStringToIPv4(ip string) (net.IP, error) {
	if len(strings.Split(ip, ".")) != 4 {
		return nil, ErrInvalidIP
	}

	ipAddr, err := net.ResolveIPAddr("ip4", ip)
	if err != nil {
		return nil, fmt.Errorf("error: resolve ip %s: %w", ip, err)
	}

	return ipAddr.IP.To4(), nil
}
