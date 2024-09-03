package dns

import (
	"fmt"
	"math/rand/v2"
	"net"
)

// HostToIP resolves the given host
// If multiple IP addresses are assigned to the host, a random one is returned
func HostToIP(host string) (string, error) {
	ips, err := net.LookupHost(host)
	if err != nil {
		return "", fmt.Errorf("error: lookup host: %w", err)
	}

	randIndex := rand.IntN(len(ips))

	return ips[randIndex], nil
}
