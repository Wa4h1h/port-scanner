package scanner

import "errors"

var (
	ErrAtLeastOneProtocolMustBeUsed   = errors.New("use at least one protocol tpc/udp")
	ErrHostUnavailable                = errors.New("host can not be pinged")
	ErrICMPResponseDontMatchEchoReply = errors.New("host did not response with echo reply")
)
