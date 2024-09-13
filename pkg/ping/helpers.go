package ping

import (
	"fmt"
	"strconv"
	"strings"
)

func IPStringToBytes(ip string) ([]byte, error) {
	ipStr := strings.Split(ip, ".")

	if len(ipStr) != 4 {
		return nil, ErrInvalidIP
	}

	ipBytes := make([]byte, 0, 4)

	for _, octet := range ipStr {
		val, err := strconv.ParseUint(octet, 10, 8)
		if err != nil {
			return nil, fmt.Errorf("error: convert str to uint: %w", err)
		}

		ipBytes = append(ipBytes, uint8(val))
	}

	return ipBytes, nil
}
