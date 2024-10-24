package scanner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	icmp2 "github.com/Wa4h1h/port-scanner/pkg/icmp"
	"golang.org/x/net/icmp"

	"github.com/Wa4h1h/port-scanner/pkg/dns"

	"github.com/Wa4h1h/port-scanner/pkg/ping"
)

func NewScanExecutor(c *Config, privilegedPing bool) ScanExecutor {
	s := new(Scanner)

	s.Cfg = c

	p := ping.NewPinger(&ping.DefaultConfig,
		ping.WithPrivileged(privilegedPing))

	s.Pg = p

	return s
}

func (s *Scanner) delayRetry() {
	time.Sleep(time.Duration(s.Cfg.DelayRetry) * time.Millisecond)
	s.Cfg.DelayRetry += IncDelayRetry
}

func (s *Scanner) listenForDstUnreachable(ip string) error {
	reply := make([]byte, UDPMaxBufferSize)

	conn, err := icmp.ListenPacket("udp4", "0.0.0.0")
	if err != nil {
		return fmt.Errorf("error: create icmp socket to listen to dst unreachable: %w", err)
	}

	defer conn.Close()

	for {
		n, addr, err := conn.ReadFrom(reply)
		if err != nil {
			return fmt.Errorf("error: reading icmp dst unreachable packet: %w", err)
		}

		if n > 0 {
			if strings.Contains(addr.String(), ip) {
				p, _ := icmp2.ParseUnreachable(reply[:n])
				if p != nil {
					break
				}
			}
		}
	}

	return nil
}

func (s *Scanner) udpScan(ip, port string) (*ScanResult, error) {
	descriptivePort := fmt.Sprintf("%s/udp", port)
	service := PortToService(descriptivePort)

	errChan := make(chan error)
	dstUnreachChan := make(chan error)
	scanRes := make(chan *ScanResult)

	ipBytes, err := ping.IPStringToBytes(ip)
	if err != nil {
		return nil, err
	}

	portInt, err := strconv.ParseInt(port, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("error: parse port: %w", err)
	}

	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{
		IP:   ipBytes,
		Port: int(portInt),
	})
	if err != nil {
		return nil, fmt.Errorf("error: dial udp: %w", err)
	}

	defer conn.Close()

	go func(e chan<- error) {
		e <- s.listenForDstUnreachable(ip)
	}(dstUnreachChan)

	go func() {
		reply := make([]byte, UDPMaxBufferSize)

		for i := 0; i < s.Cfg.BackoffLimit; {
			_, err = conn.Write([]byte{0x0})
			if err != nil {
				i++

				s.delayRetry()

				continue
			}

			if err = conn.SetReadDeadline(time.Now().
				Add(time.Duration(s.Cfg.Timeout) * time.Second)); err != nil {
				i++

				s.delayRetry()

				continue
			}

			var (
				n    int
				addr net.Addr
			)

			n, addr, err = conn.ReadFrom(reply)
			if err != nil {
				i++

				s.delayRetry()

				continue
			}

			if strings.Contains(addr.String(), ip) {
				if n > 0 {
					scanRes <- &ScanResult{
						State:   Open,
						Port:    descriptivePort,
						Service: service,
					}

					return
				}

				i++
			}
		}

		errChan <- err
	}()

	for {
		select {
		case dstUnreach := <-dstUnreachChan:
			if dstUnreach == nil {
				return &ScanResult{
					State:   Closed,
					Port:    descriptivePort,
					Service: service,
				}, nil
			}
		case err = <-errChan:
			var netErr *net.OpError
			if errors.As(err, &netErr) && netErr.Timeout() {
				return &ScanResult{
					State:   Filtered,
					Port:    descriptivePort,
					Service: service,
				}, nil
			}

			return nil, err
		case res := <-scanRes:
			return res, nil
		}
	}
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

// PingHost resolves host and ping it
func (s *Scanner) PingHost(host string) (*ping.Stats, string, error) {
	ctx, cancle := context.WithTimeout(context.Background(),
		time.Duration(s.Cfg.Timeout)*time.Second)
	defer cancle()

	ip, err := dns.HostToIP(ctx, host)
	if err != nil {
		return nil, "", err
	}

	var stats *ping.Stats

	stats, err = s.Pg.Ping(ip)
	if err != nil {
		if strings.Contains(err.Error(), "sendto: no route to host") {
			return nil, "", fmt.Errorf("%s %w", host, ErrHostUnavailable)
		}

		return nil, "", err
	}

	if !stats.Up {
		return nil, "", fmt.Errorf("ping %s(%s) failed: %w. Scanning aborted",
			host, ip, ErrICMPResponseDontMatchEchoReply)
	}

	return stats, ip, nil
}

type scanResultError struct {
	result *ScanResult
	err    error
}

// Scan performs TCP and UDP port scanning if enabled in the configuration.
func (s *Scanner) Scan(ip, port string) ([]*ScanResult, error) {
	var (
		wg  sync.WaitGroup
		err error
	)

	resErrChan := make(chan *scanResultError, NumberOfScans)
	results := make([]*ScanResult, 0, NumberOfScans)

	if !s.Cfg.UDP && !s.Cfg.TCP {
		return nil, ErrAtLeastOneProtocolMustBeUsed
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
		return nil, err
	}

	return results, nil
}

// SynScan performs a TCP half-open connection scan.
func (s *Scanner) SynScan(host, port string) (*ping.Stats,
	[]*ScanResult, error,
) {
	return nil, nil, nil
}

// RangeScan scan all the provided ports(tcp,udp and syn if enabled) on the provided host.
func (s *Scanner) RangeScan(host string,
	ports []string,
) (*ping.Stats, []*ScanResult, error) {
	var (
		stats       *ping.Stats
		ip          string
		err         error
		scanResults = make([]*ScanResult, 0)
	)

	stats, ip, err = s.PingHost(host)
	if err != nil {
		return nil, nil, err
	}

	for _, p := range ports {
		res, err := s.Scan(ip, p)
		if err != nil {
			return nil, nil, err
		}

		scanResults = append(scanResults, res...)
	}

	return stats, scanResults, nil
}

// VanillaScan scans 0-65535 ports(tcp,udp and syn if enabled).
func (s *Scanner) VanillaScan(host string) (*ping.Stats,
	[]*ScanResult, error,
) {
	ports := make([]string, 0, LastPort)

	for i := range LastPort {
		ports = append(ports, fmt.Sprintf("%d", i+1))
	}

	return s.RangeScan(host, ports)
}

// SweepScan scans port (TCP, UDP and SYN if enabled) on each host from the provided host list.
func (s *Scanner) SweepScan(hosts []string,
	port string,
) ([]*SweepScanResult, error) {
	return nil, nil
}
