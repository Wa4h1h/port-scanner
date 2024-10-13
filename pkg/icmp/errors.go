package icmp

import "errors"

var (
	ErrBodyIsNotICMPEchoReply      = errors.New("body is not icmp echo reply")
	ErrBodyIsNotICMPDstUnreachable = errors.New("body is not icmp destination unreachable")
)
