package cli

import "errors"

var ErrHostsMissing = errors.New("hosts are missing: provide at least one host/ip")
