package scanner

import "fmt"

const (
	DefaultTimeout      int = 1
	DefaultCScan        int = 3
	NumberOfScans       int = 2
	DefaultBackoffLimit int = 3
	UDPMaxBufferSize    int = 1500
	DefaultDelayRetry   int = 15
	IncDelayRetry       int = 5
	LastPort            int = 65535
)

type Proto string

const (
	TCP Proto = "tcp"
	UDP Proto = "udp"
)

var ianaPorts = make([]string, 0, LastPort)

func init() {
	for i := range LastPort {
		ianaPorts = append(ianaPorts, fmt.Sprintf("%d", i+1))
	}
}
