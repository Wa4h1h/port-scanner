package scanner

import "github.com/Wa4h1h/networki/pkg/ping"

// make sure we conform to ScanExecutor.
var _ ScanExecutor = &Scanner{}

type State string

const (
	Open     State = "open"
	Filtered State = "filtered"
	Closed   State = "closed"
)

type ScanResult struct {
	Service string
	Port    string
	State   State
}

type SweepScanResult struct {
	Host      string
	IP        string
	PingStats *ping.Stats
	ScanResult
}

type Config struct {
	Timeout      int
	CScan        int
	BackoffLimit int
	TCP          bool
	UDP          bool
	SYN          bool
}

type Scanner struct {
	Cfg *Config
	Pg  ping.Pinger
}

type ScanExecutor interface {
	Scan(host string, port string) (*ping.Stats, []*ScanResult, error)
	SynScan(host string, port string) (*ping.Stats, []*ScanResult, error)
	RangeScan(host string, ports []string) (*ping.Stats, []*ScanResult, error)
	VanillaScan(host string) (*ping.Stats, []*ScanResult, error)
	SweepScan(hosts []string, port string) ([]*SweepScanResult, error)
}
