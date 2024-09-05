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
		return "", fmt.Errorf("error: lookup host: %w", err)
	}

	randIndex := rand.IntN(len(ips))

	return ips[randIndex].String(), nil
}
