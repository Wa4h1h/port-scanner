package ping

import "errors"

var (
	ErrUnvalidIP   = errors.New("ip is not ipv4")
	ErrWrongSender = errors.New("received response from unknown ip")
)