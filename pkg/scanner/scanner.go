package scanner

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"github.com/Wa4h1h/port-scanner/pkg/tcp"

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

// UdpScan performs a single udp scan
func (s *Scanner) UDPScan(ip, port string) (*ScanResult, error) {
	defer func() {
		s.Cfg.DelayRetry = DefaultDelayRetry
	}()

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

// TCPScan performs a single tcp scan
func (s *Scanner) TCPScan(ip, port string) (*ScanResult, error) {
	defer func() {
		s.Cfg.DelayRetry = DefaultDelayRetry
	}()

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

				s.delayRetry()

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
func (s *Scanner) PingHost(host string) (*ping.Stats, error) {
	ctx, cancel := context.WithTimeout(context.Background(),
		time.Duration(s.Cfg.Timeout)*time.Second)
	defer cancel()

	ip, err := dns.HostToIP(ctx, host)
	if err != nil {
		return nil, err
	}

	var stats *ping.Stats

	stats, err = s.Pg.Ping(ip)
	if err != nil {
		if strings.Contains(err.Error(), "sendto: no route to host") {
			return nil, fmt.Errorf("%s %w", host, ErrHostUnavailable)
		}

		return nil, err
	}

	if !stats.Up {
		return nil, fmt.Errorf("ping %s(%s) failed: %w",
			host, ip, ErrICMPResponseDontMatchEchoReply)
	}

	return stats, nil
}

type scanResultError struct {
	result *ScanResult
	err    error
}

func (s *Scanner) execScan(ip, port string, scanType ScanType,
	wg *sync.WaitGroup, r chan<- *scanResultError,
) {
	var (
		start time.Time
		end   time.Duration
		res   *ScanResult
		err   error
	)

	defer wg.Done()

	start = time.Now()

	switch scanType {
	case UDP:
		res, err = s.UDPScan(ip, port)
	case TCP:
		res, err = s.TCPScan(ip, port)
	case SYN:
		res, err = s.SynScan(ip, port)
	}

	end = time.Since(start)
	res.Rtt = math.Floor(end.Seconds()*100) / 100

	r <- &scanResultError{
		err:    err,
		result: res,
	}
}

// Scan performs TCP and UDP port scanning if enabled in the configuration.
func (s *Scanner) scan(ip, port string) ([]*ScanResult, []error) {
	var (
		wg   sync.WaitGroup
		errs = make([]error, 0)
	)

	resErrChan := make(chan *scanResultError, NumberOfScans)
	results := make([]*ScanResult, 0, NumberOfScans)

	if !s.Cfg.UDP && !s.Cfg.TCP && !s.Cfg.SYN {
		return nil, []error{ErrAtLeastOneProtocolMustBeUsed}
	}

	if s.Cfg.TCP {
		wg.Add(1)

		go s.execScan(ip, port, TCP, &wg, resErrChan)
	}

	if s.Cfg.UDP {
		wg.Add(1)

		go s.execScan(ip, port, UDP, &wg, resErrChan)
	}

	if s.Cfg.SYN {
		wg.Add(1)

		go s.execScan(ip, port, SYN, &wg, resErrChan)
	}

	go func(r chan *scanResultError) {
		wg.Wait()

		close(r)
	}(resErrChan)

	for val := range resErrChan {
		if val.err != nil {
			errs = append(errs, val.err)
		}

		if val.result != nil {
			results = append(results, val.result)
		}
	}

	return results, errs
}

type ReadPacket struct {
	TCPPacket []byte
	Err       error
}

// listenForIPPackets listen for all incoming ipv4 packets
// returns the packet payload coming from the source IP
func (s *Scanner) listenForIPPackets(netIntf string, src net.IP) *ReadPacket {
	var readPacket ReadPacket

	// Open the device for capturing
	handle, err := pcap.OpenLive(netIntf, 1600, true, pcap.BlockForever)
	if err != nil {
		readPacket.Err = fmt.Errorf("error: open pcap: %w", err)

		return &readPacket
	}
	defer handle.Close()

	filter := "ip"

	err = handle.SetBPFFilter(filter)
	if err != nil {
		readPacket.Err = fmt.Errorf("error: set BPFFilter: %w", err)

		return &readPacket
	}

	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// Check for the IP layer
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)

			if ip.SrcIP.Equal(src) {
				readPacket.TCPPacket = ip.Payload

				break
			}
		}
	}

	return &readPacket
}

// SynScan performs a TCP half-open connection scan.
func (s *Scanner) SynScan(ip, port string) (*ScanResult, error) {
	listenChan := make(chan *ReadPacket)
	localIP, inter := GetLocalIP()

	descriptivePort := fmt.Sprintf("%s/tcp", port)
	service := PortToService(descriptivePort)

	srcAddr, err := ping.IPStringToBytes(localIP)
	if err != nil {
		return nil, err
	}

	dstAddr, err := ping.IPStringToBytes(ip)
	if err != nil {
		return nil, err
	}

	go func() {
		listenChan <- s.listenForIPPackets(inter, dstAddr)
	}()

	conn, err := net.DialIP("ip4:tcp", &net.IPAddr{
		IP: srcAddr,
	}, &net.IPAddr{
		IP: dstAddr,
	})
	if err != nil {
		return nil, fmt.Errorf("error: dial %s:%s: %w", ip, port, err)
	}

	defer conn.Close()

	srcPort, err := GetFreePort()
	if err != nil {
		return nil, err
	}

	dstPort, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("error: pares port %s to uin16: %w", port, err)
	}

	tcpHeader := tcp.TCPHeader{
		SeqNum:    rand.Uint32(),
		AckNum:    0,
		SrcPort:   srcPort,
		DstPort:   uint16(dstPort),
		Window:    0xffff,
		Checksum:  0,
		Ptr:       0,
		CtrlFlags: tcp.SYN,
		Offset:    5,
		Reserved:  0,
		Options:   make([]byte, 0),
	}

	packet := tcp.Packet{
		Header: &tcpHeader,
		Body:   make([]byte, 0),
	}

	b, err := packet.Marshal()
	if err != nil {
		return nil, err
	}

	csum, err := tcp.CheckSum(b, srcAddr, dstAddr)
	if err != nil {
		return nil, err
	}

	packet.Header.Checksum = csum

	b, err = packet.Marshal()
	if err != nil {
		return nil, err
	}

	_, err = conn.Write(b)
	if err != nil {
		return nil, err
	}

	tmp := <-listenChan

	if tmp.Err != nil {
		return nil, err
	}

	if err := packet.Unmarshal(tmp.TCPPacket); err != nil {
		return nil, err
	}

	sr := ScanResult{
		Service: service,
		Port:    port,
	}

	if packet.FlagIsSYNACK() {
		sr.State = Open
	} else if packet.FlagIsRST() {
		sr.State = Closed
	}

	return &sr, nil
}

// Scan scan all the provided ports(tcp,udp and syn if enabled) on the provided host.
func (s *Scanner) Scan(host string,
	ports []string,
) ([]*ScanResult, *Stats, []error) {
	var (
		pingStats   *ping.Stats
		dnsInfo     = new(dns.DNSInfo)
		stats       *Stats
		err         error
		scanResults = make([]*ScanResult, 0)
		errs        = make([]error, 0)
	)

	dnsInfo.IP, err = dns.HostToIP(context.Background(), host)
	if err != nil {
		errs = append(errs, err)

		return nil, nil, errs
	}

	dnsInfo.RDns = dns.IPToHost(dnsInfo.IP)

	if s.Cfg.Ping {
		pingStats, err = s.PingHost(host)
		if err != nil {
			errs = append(errs, err)
		}
	}

	var (
		tmpRes []*ScanResult
		tmpErr []error
		accRtt float64
	)

	for _, p := range ports {
		tmpRes, tmpErr = s.scan(dnsInfo.IP, p)

		for _, res := range tmpRes {
			accRtt += res.Rtt
		}

		scanResults = append(scanResults, tmpRes...)
		errs = append(errs, tmpErr...)
	}

	stats = &Stats{
		Rtt: accRtt,
		DNS: dnsInfo,
	}

	if pingStats != nil {
		stats.Ping = pingStats
	}

	return scanResults, stats, errs
}

// VanillaScan scans 0-65535 ports(tcp,udp and syn if enabled).
func (s *Scanner) VanillaScan(host string) (
	[]*ScanResult, *Stats, []error,
) {
	return s.Scan(host, ianaPorts)
}

// SweepScan scans port (TCP, UDP and SYN if enabled) on each host from the provided host list.
func (s *Scanner) SweepScan(hosts []string,
	port string,
) ([]*SweepScanResult, float64) {
	sweepScanResults := make([]*SweepScanResult, 0, len(hosts))

	var accRtt float64

	for _, h := range hosts {
		tmpResults := &SweepScanResult{
			Host: h,
			Errs: make([]error, 0),
		}

		sresult, stats, tmpErrs := s.Scan(h, []string{port})
		if len(tmpErrs) != 0 {
			tmpResults.Errs = append(tmpResults.Errs,
				tmpErrs...)
		} else {
			accRtt += stats.Rtt
			tmpResults.ScanResults = sresult
			tmpResults.Stats = stats

			if stats.DNS != nil {
				tmpResults.IP = stats.DNS.IP
			}
		}

		sweepScanResults = append(sweepScanResults, tmpResults)
	}

	return sweepScanResults, accRtt
}
