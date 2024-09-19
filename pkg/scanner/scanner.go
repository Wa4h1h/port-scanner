package scanner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/Wa4h1h/networki/pkg/dns"

	"github.com/Wa4h1h/networki/pkg/ping"
)

func NewScanExecutor(c *Config, privilegedPing bool) ScanExecutor {
	s := new(Scanner)

	s.Cfg = c

	p := ping.NewPinger(&ping.DefaultConfig,
		ping.WithPrivileged(privilegedPing))

	s.Pg = p

	return s
}

func (s *Scanner) udpScan(ip, port string) (*ScanResult, error) {
	return nil, nil
}

func (s *Scanner) tcpScan(ip, port string) (*ScanResult, error) {
	descriptivePort := fmt.Sprintf("%s/tcp", port)
	service := PortToService(descriptivePort)

	for i := 0; i < s.Cfg.BackoffLimit; {
		conn, err := net.DialTimeout("tcp",
			fmt.Sprintf("%s:%s", ip, port),
			time.Duration(s.Cfg.Timeout)*time.Second)
		if err != nil {
			if strings.Contains(err.Error(), "connect: connection refused") {
				return &ScanResult{
					State:   Closed,
					Port:    descriptivePort,
					Service: service,
				}, nil
			}

			var nErr net.Error
			if errors.As(err, &nErr) && nErr.Timeout() {
				i++

				continue
			}

			return nil, fmt.Errorf("error: connect to %s:%s: %w", ip, port, err)
		}

		conn.Close()

		return &ScanResult{
			State:   Open,
			Port:    descriptivePort,
			Service: service,
		}, nil
	}

	return &ScanResult{
		State:   Filtered,
		Port:    descriptivePort,
		Service: service,
	}, nil
}

// getIP resolves host and ping it
func (s *Scanner) getIP(host string) (*ping.Stats, string, error) {
	ctx, cancle := context.WithTimeout(context.Background(),
		time.Duration(s.Cfg.Timeout)*time.Second)
	defer cancle()

	ip, err := dns.HostToIP(ctx, host)
	if err != nil {
		return nil, "", err
	}

	var pres *ping.Stats

	pres, err = s.Pg.Ping(ip)
	if err != nil {
		if strings.Contains(err.Error(), "sendto: no route to host") {
			return nil, "", fmt.Errorf("%s %w", host, ErrHostUnavailable)
		}

		return nil, "", err
	}

	if !pres.Up {
		return nil, "", ErrICMPResponseDontMatchEchoReply
	}

	return pres, ip, nil
}

type scanResultError struct {
	result *ScanResult
	err    error
}

// Scan performs TCP and UDP port scanning if enabled in the configuration.
func (s *Scanner) Scan(host, port string) (*ping.Stats, []*ScanResult, error) {
	var (
		wg    sync.WaitGroup
		err   error
		ip    string
		stats *ping.Stats
	)

	resErrChan := make(chan *scanResultError, NumberOfScans)
	results := make([]*ScanResult, 0, NumberOfScans)

	stats, ip, err = s.getIP(host)
	if err != nil {
		return nil, nil, err
	}

	if !s.Cfg.UDP && !s.Cfg.TCP {
		return nil, nil, ErrAtLeastOneProtocolMustBeUsed
	}

	if s.Cfg.TCP {
		wg.Add(1)

		go func(r chan<- *scanResultError) {
			defer wg.Done()

			res, err := s.tcpScan(ip, port)

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

			res, err := s.udpScan(ip, port)

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
		return nil, nil, err
	}

	return stats, results, nil
}

// SynScan performs a TCP half-open connection scan.
func (s *Scanner) SynScan(host, port string) (*ping.Stats, []*ScanResult, error) {
	return nil, nil, nil
}

// RangeScan scan all the provided ports(tcp,udp and syn if enabled) on the provided host.
func (s *Scanner) RangeScan(host string,
	ports []string,
) (*ping.Stats, []*ScanResult, error) {
	return nil, nil, nil
}

// VanillaScan scans 1-65535 ports(tcp,udp and syn if enabled).
func (s *Scanner) VanillaScan(host string) (*ping.Stats, []*ScanResult, error) {
	return nil, nil, nil
}

// SweepScan scans port (TCP, UDP and SYN if enabled) on each host from the provided host list.
func (s *Scanner) SweepScan(hosts []string,
	port string,
) ([]*SweepScanResult, error) {
	return nil, nil
}
