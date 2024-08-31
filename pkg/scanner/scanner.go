package scanner

import "fmt"

func NewScanner(c *Config) *Scanner {
	return &Scanner{
		cfg: c,
	}
}

func (s *Scanner) Scan(host, port string) (*ScanResult, error) {
	return nil, nil
}

func (s *Scanner) SynScan(host, port string) (*ScanResult, error) {
	return nil, nil
}

func (s *Scanner) RangeScan(host string,
	ports []string,
) ([]ScanResult, error) {
	fmt.Println(ports)
	return nil, nil
}

func (s *Scanner) VanillaScan(host string) ([]ScanResult, error) {
	return nil, nil
}

func (s *Scanner) SweepScan(hosts []string,
	port string,
) ([]SweepScanResult, error) {
	return nil, nil
}
