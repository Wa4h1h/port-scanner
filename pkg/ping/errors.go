package ping

import "errors"

var (
	ErrInvalidIP = errors.New("ip is not ipv4")
)
