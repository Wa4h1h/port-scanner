package scanner

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
}

var DefaultConfig = Config{
	TCP:     true,
	UDP:     false,
	SYN:     false,
	Timeout: DefaultTimeout,
	CScan:   DefaultCScan,
}

type ScanExecutor interface {
	Scan(string, string) ([]*ScanResult, error)
	SynScan(string, string) ([]*ScanResult, error)
	RangeScan(string, []string) ([]*ScanResult, error)
	VanillaScan(string) ([]*ScanResult, error)
	SweepScan([]string, string) ([]*SweepScanResult, error)
}
