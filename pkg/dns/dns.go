package dns

import (
	"fmt"
	"math/rand/v2"
	"net"
)

func HostToIP(host string) (string, error) {
	ips, err := net.LookupHost(host)
	if err != nil {
		return "", fmt.Errorf("error: lookup host: %w", err)
	}

	randIndex := rand.IntN(len(ips))

	return ips[randIndex], nil
}