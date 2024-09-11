package ping

import "errors"

var (
	ErrInvalidIP              = errors.New("ip is not ipv4")
	ErrRcvDidNotReceivePacket = errors.New("did not receive intended packet")
)
