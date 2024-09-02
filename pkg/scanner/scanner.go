package scanner

import (
	"errors"
	"fmt"
	"sync"
)

// make sure we conform to ScanExecutor.
var _ ScanExecutor = &Scanner{}

func NewScanner(c *Config) ScanExecutor {
	s := new(Scanner)

	if c != nil {
		s.Cfg = c
	} else {
		s.Cfg = &DefaultConfig
	}

	return s
}

func (s *Scanner) udpScan(host, port string) (*ScanResult, error) {
	return nil, nil
}

func (s *Scanner) tcpScan(host, port string) (*ScanResult, error) {
	return nil, nil
}

type scanResultError struct {
	result *ScanResult
	err    error
}

// Scan performs TCP and UDP port scanning if enabled in the configuration.
func (s *Scanner) Scan(host, port string) ([]*ScanResult, error) {
	var wg sync.WaitGroup

	resErrChan := make(chan *scanResultError, 2)
	results := make([]*ScanResult, 2)

	if !s.Cfg.UDP && !s.Cfg.TCP {
		return nil, ErrAtLeastOneProtocolMustBeUsed
	}

	if s.Cfg.TCP {
		wg.Add(1)

		go func(r chan<- *scanResultError) {
			defer wg.Done()

			res, err := s.tcpScan(host, port)

			r <- &scanResultError{
				err:    err,
				result: res,
			}
		}(resErrChan)
	}

	if s.Cfg.UDP {
		wg.Add(1)

		go func(r chan<- *scanResultError) {
			defer wg.Done()

			res, err := s.udpScan(host, port)

			r <- &scanResultError{
				err:    err,
				result: res,
			}
		}(resErrChan)
	}

	go func(r chan *scanResultError) {
		wg.Wait()

		close(r)
	}(resErrChan)

	var err error

	for val := range resErrChan {
		if val.err != nil {
			err = errors.Join(err, val.err)
		} else {
			results = append(results, val.result)
		}
	}

	if err != nil {
		return nil, err
	}

	return results, nil
}

// SynScan performs a TCP half-open connection scan if enabled in the configuration.
func (s *Scanner) SynScan(host, port string) ([]*ScanResult, error) {
	return nil, nil
}

// RangeScan scan all the provided ports(tcp,udp and syn if enabled) on the provided host.
func (s *Scanner) RangeScan(host string,
	ports []string,
) ([]*ScanResult, error) {
	fmt.Println(ports)
	return nil, nil
}

// VanillaScan scans the 65535 ports(tcp,udp and syn if enabled).
func (s *Scanner) VanillaScan(host string) ([]*ScanResult, error) {
	return nil, nil
}

// SweepScan scans the port (TCP, UDP and SYN if enabled) on each host from the provided host list.
func (s *Scanner) SweepScan(hosts []string,
	port string,
) ([]*SweepScanResult, error) {
	return nil, nil
}
