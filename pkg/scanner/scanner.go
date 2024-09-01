package scanner

import (
	"errors"
	"fmt"
	"sync"
)

func NewScanner(c *Config) *Scanner {
	s := new(Scanner)

	if c != nil {
		s.cfg = c
	} else {
		s.cfg = &DefaultConfig
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

func (s *Scanner) Scan(host, port string) ([]*ScanResult, error) {
	var (
		wg  sync.WaitGroup
		err error
	)

	resErrChan := make(chan *scanResultError, 2)
	results := make([]*ScanResult, 2)

	if !s.cfg.UDP && !s.cfg.TCP {
		return nil, ErrAtLeastOneProtocolMustBeUsed
	}

	if s.cfg.TCP {
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

	if s.cfg.UDP {
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

func (s *Scanner) SynScan(host, port string) ([]*ScanResult, error) {
	return nil, nil
}

func (s *Scanner) RangeScan(host string,
	ports []string,
) ([]*ScanResult, error) {
	fmt.Println(ports)
	return nil, nil
}

func (s *Scanner) VanillaScan(host string) ([]*ScanResult, error) {
	return nil, nil
}

func (s *Scanner) SweepScan(hosts []string,
	port string,
) ([]*SweepScanResult, error) {
	return nil, nil
}
