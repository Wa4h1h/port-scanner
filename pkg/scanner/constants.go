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

type ScanType string

const (
	TCP ScanType = "tcp"
	UDP ScanType = "udp"
	SYN ScanType = "syn"
)

var ianaPorts = make([]string, 0, LastPort)

func init() {
	for i := range LastPort {
		ianaPorts = append(ianaPorts, fmt.Sprintf("%d", i+1))
	}
}
