package dns

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net"
)

// HostToIP resolves the given host
// If multiple IP addresses are assigned to the host, a random one is returned
func HostToIP(ctx context.Context, host string) (string, error) {
	var r net.Resolver

	ips, err := r.LookupIP(ctx, "ip4", host)
	if err != nil {
		return "", fmt.Errorf("error: lookup host(%s): %w", host, err)
	}

	randIndex := rand.IntN(len(ips))

	return ips[randIndex].String(), nil
}

// IPToHost do reverse DNS of ip
// If multiple Addresses are assigned to the ip, a random one is returned
func IPToHost(ip string) (string, error) {
	names, err := net.LookupAddr(ip)
	if err != nil {
		return "", fmt.Errorf("error: reverse lookup addr(%s): %w", ip, err)
	}

	randIndex := rand.IntN(len(names))

	return names[randIndex], nil
}
