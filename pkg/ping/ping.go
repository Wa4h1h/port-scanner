package ping

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/Wa4h1h/port-scanner/pkg/dns"

	"golang.org/x/net/ipv4"

	"golang.org/x/net/icmp"
)

func NewPinger(timeout int,
	readNumTries int,
	privileged bool,
) Pinger {
	return &Ping{
		timeout:      timeout,
		readNumTries: readNumTries,
		privileged:   privileged,
	}
}

func (p *Ping) sendPing(ipBytes []byte, e chan<- error) {
	var (
		err error
		b   []byte
	)

	m := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  33434,
			Data: []byte{0x0},
		},
	}

	b, err = m.Marshal(nil)
	if err != nil {
		e <- fmt.Errorf("error: marshal ICMP echo: %w", err)

		return
	}

	err = p.conn.SetWriteDeadline(time.Now().Add(time.Duration(p.timeout) * time.Second))
	if err != nil {
		e <- fmt.Errorf("error: set ping write timeout: %w", err)

		return
	}

	_, err = p.conn.WriteTo(b, &net.UDPAddr{
		IP:   ipBytes,
		Port: 33434,
	})
	if err != nil {
		e <- fmt.Errorf("error: ping: %w", err)

		return
	}
}

func (p *Ping) readPing(e chan<- error, d chan<- bool) {
	resp := make([]byte, 0)
	tries := 0

	for tries <= p.readNumTries {
		tmp := make([]byte, 512)

		if err := p.conn.SetReadDeadline(time.Now().
			Add(time.Duration(p.timeout) * time.Second)); err != nil {
			e <- fmt.Errorf("error: set read deadline: %w", err)

			return
		}

		n, _, err := p.conn.ReadFrom(tmp)
		if err != nil {
			if tries+1 > p.readNumTries {
				e <- fmt.Errorf("error: ping: %w", err)

				return
			}

			tries++

			continue
		}

		resp = append(resp, tmp[:n]...)

		if (n == 0 || n < 512) && n > 4 {
			ok, err := p.isEchoReply(resp)
			if err != nil {
				e <- err
			} else {
				d <- ok
			}

			return
		}
	}
}

func (p *Ping) Ping(host string) (bool, error) {
	var (
		err     error
		ipBytes []byte
		ip      string
	)

	ctx, cancel := context.WithTimeout(context.Background(),
		time.Duration(p.timeout)*time.Second)
	defer cancel()

	ip, err = dns.HostToIP(ctx, host)
	if err != nil {
		return false, err
	}

	switch {
	case p.privileged:
		p.conn, err = icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	default:
		p.conn, err = icmp.ListenPacket("udp4", "0.0.0.0")
	}

	defer p.conn.Close()

	if err != nil {
		return false, fmt.Errorf("error: create socket: %w", err)
	}

	errChan := make(chan error)
	done := make(chan bool)

	ipBytes, err = IPStringToBytes(ip)
	if err != nil {
		return false, err
	}

	go p.sendPing(ipBytes, errChan)

	go p.readPing(errChan, done)

	select {
	case err = <-errChan:
		return false, err
	case ok := <-done:
		return ok, nil
	}
}

func (p *Ping) isEchoReply(bytes []byte) (bool, error) {
	m, err := icmp.ParseMessage(1, bytes)
	if err != nil {
		return false, fmt.Errorf("error: parse icmp message: %w", err)
	}

	return m.Type == ipv4.ICMPTypeEchoReply, nil
}
