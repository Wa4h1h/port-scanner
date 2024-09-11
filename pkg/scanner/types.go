package scanner

import "github.com/Wa4h1h/networki/pkg/ping"

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
	Host string
	IP   string
	ScanResult
}

type Config struct {
	Timeout int
	CScan   int
	Retries int
	TCP     bool
	UDP     bool
	SYN     bool
}

type Scanner struct {
	Cfg *Config
	Pg  ping.Pinger
}

var DefaultConfig = Config{
	TCP:     true,
	UDP:     false,
	SYN:     false,
	Timeout: DefaultTimeout,
	CScan:   DefaultCScan,
	Retries: DefaultRetries,
}

type ScanExecutor interface {
	Scan(host string, port string) ([]*ScanResult, error)
	SynScan(host string, port string) ([]*ScanResult, error)
	RangeScan(host string, ports []string) ([]*ScanResult, error)
	VanillaScan(host string) ([]*ScanResult, error)
	SweepScan(hosts []string, port string) ([]*SweepScanResult, error)
}
