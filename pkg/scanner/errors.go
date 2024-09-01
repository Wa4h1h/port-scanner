package scanner

import "errors"

var ErrAtLeastOneProtocolMustBeUsed = errors.New("use at least one protocol tpc/udp")
