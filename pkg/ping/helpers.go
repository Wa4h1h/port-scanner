package ping

import (
	"fmt"
	"strconv"
	"strings"
)

func IPStringToBytes(ip string) ([]byte, error) {
	ipStr := strings.Split(ip, ".")

	if len(ipStr) != 4 {
		return nil, ErrUnvalidIP
	}

	ipBytes := make([]byte, 0)

	for _, octet := range ipStr {
		val, err := strconv.ParseUint(octet, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("error: convert str to uint: %w", err)
		}

		ipBytes = append(ipBytes, uint8(val))
	}

	return ipBytes, nil
}
