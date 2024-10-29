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
	// Rtt(round trip) of a single scan in seconds
	Rtt float64
	// service name
	Service string
	// service port
	Port string
	// scan state
	// open when host is ready to accept connection
	// filtered when host did not return a response/timed out
	// closed when the host returns icmp type 3 code 13(dst unreachable) or RST packet
	State State
}

type SweepScanResult struct {
	Host        string
	IP          string
	Stats       *Stats
	ScanResults []*ScanResult
	Errs        []error
}

type Config struct {
	// scan timeout
	Timeout int
	// max number of concurrent scans
	CScan int
	// number scan retries
	BackoffLimit int
	// Time until a scan is attempted again
	DelayRetry int
	// enable tcp scan
	TCP bool
	// enable udp scan
	UDP bool
	// enable half open connection scan
	SYN bool
	// enable ping before scanning
	Ping bool
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
	SynScan(ip string, port string) (*ScanResult, error)
	UDPScan(ip, port string) (*ScanResult, error)
	TCPScan(ip, port string) (*ScanResult, error)
	Scan(host string, ports []string) ([]*ScanResult, *Stats, []error)
	VanillaScan(host string) ([]*ScanResult, *Stats, []error)
	SweepScan(hosts []string, port string) ([]*SweepScanResult, float64)
}
