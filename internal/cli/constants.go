package cli

import "github.com/Wa4h1h/port-scanner/pkg/scanner"

const (
	DefaultTimeout     int    = scanner.DefaultTimeout
	DefaultCScan       int    = scanner.DefaultCScan
	UDP                bool   = false
	TCP                bool   = true
	SYN                bool   = false
	Vanilla            bool   = false
	UseDefaultSettings bool   = true
	Ports              string = "80"
)
