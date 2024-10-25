package scanner

import (
	"github.com/Wa4h1h/port-scanner/pkg/dns"
	"github.com/Wa4h1h/port-scanner/pkg/ping"
)

// make sure we conform to ScanExecutor.
var _ ScanExecutor = &Scanner{}

type State string

const (
	Open     State = "open"
	Filtered State = "filtered"
	Closed   State = "closed"
)

type ScanResult struct {
	Rtt     float64
	Service string
	Port    string
	State   State
}

type SweepScanResult struct {
	Host        string
	IP          string
	Stats       *Stats
	ScanResults []*ScanResult
}

type Config struct {
	Timeout      int
	CScan        int
	BackoffLimit int
	DelayRetry   int
	TCP          bool
	UDP          bool
	SYN          bool
	Ping         bool
}

var DefaultConfig = Config{
	Timeout:      DefaultTimeout,
	CScan:        DefaultCScan,
	BackoffLimit: DefaultBackoffLimit,
	DelayRetry:   DefaultDelayRetry,
	TCP:          true,
	UDP:          false,
	SYN:          false,
	Ping:         false,
}

type Stats struct {
	DNS  *dns.DNSInfo
	Ping *ping.Stats
	Rtt  float64
}

type Scanner struct {
	Cfg *Config
	Pg  ping.Pinger
}

type ScanExecutor interface {
	PingHost(host string) (*ping.Stats, error)
	SynScan(ip string, port string) ([]*ScanResult, *Stats, error)
	UdpScan(ip, port string) (*ScanResult, error)
	TcpScan(ip, port string) (*ScanResult, error)
	Scan(host string, ports []string) ([]*ScanResult, *Stats, []error)
	VanillaScan(host string) ([]*ScanResult, *Stats, []error)
	SweepScan(hosts []string, port string) ([]*SweepScanResult, float64, []error)
}
