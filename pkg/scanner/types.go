package scanner

import "github.com/Wa4h1h/port-scanner/pkg/ping"

type ScanResult struct {
	Service string
	State   string
	Port    uint16
}

type SweepScanResult struct {
	Host string
	IP   string
	ScanResult
}

type Config struct {
	TCP     bool
	UDP     bool
	SYN     bool
	Timeout int
	CScan   int
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
}

type ScanExecutor interface {
	Scan(host string, port string) ([]*ScanResult, error)
	SynScan(host string, port string) ([]*ScanResult, error)
	RangeScan(host string, ports []string) ([]*ScanResult, error)
	VanillaScan(host string) ([]*ScanResult, error)
	SweepScan(hosts []string, port string) ([]*SweepScanResult, error)
}
