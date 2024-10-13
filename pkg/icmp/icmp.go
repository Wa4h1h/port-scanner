package icmp

import (
	"fmt"

	"golang.org/x/net/icmp"
)

func ParseEchoReply(bytes []byte) (*icmp.Echo, error) {
	m, err := icmp.ParseMessage(1, bytes)
	if err != nil {
		return nil, fmt.Errorf("error: parse icmp message: %w", err)
	}

	echo, ok := m.Body.(*icmp.Echo)
	if !ok {
		return nil, ErrBodyIsNotICMPEchoReply
	}

	return echo, nil
}

func ParseUnreachable(bytes []byte) (*icmp.DstUnreach, error) {
	m, err := icmp.ParseMessage(1, bytes)
	if err != nil {
		return nil, fmt.Errorf("error: parse icmp message: %w", err)
	}

	dstUnreach, ok := m.Body.(*icmp.DstUnreach)
	if !ok {
		return nil, ErrBodyIsNotICMPDstUnreachable
	}

	return dstUnreach, nil
}
