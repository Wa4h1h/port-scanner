package cli

import "errors"

var (
	ErrHostsMissing   = errors.New("hosts are missing: provide at least one host/ip")
	ErrRangeStrLength = errors.New("range string must be 2 of length")
)
