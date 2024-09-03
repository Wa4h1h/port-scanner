package scanner

import "errors"

var (
	ErrAtLeastOneProtocolMustBeUsed = errors.New("use at least one protocol tpc/udp")
	ErrHostUnavailable              = errors.New("host can not be pinged")
)
