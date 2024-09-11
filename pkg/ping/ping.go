package ping

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"net"
	"time"

	"github.com/Wa4h1h/networki/pkg/dns"

	"golang.org/x/net/ipv4"

	"golang.org/x/net/icmp"
)

func NewPinger(c *Config, options ...func(ping *Ping)) Pinger {
	p := &Ping{
		cfg: c,
	}

	for _, o := range options {
		o(p)
	}

	return p
}

func WithPrivileged(privileged bool) func(*Ping) {
	return func(ping *Ping) {
		ping.cfg.privileged = privileged
	}
}

func WithNumPings(numPings int) func(*Ping) {
	return func(ping *Ping) {
		ping.cfg.pingNum = numPings
	}
}

func (p *Ping) delayRetry() {
	time.Sleep(time.Duration(p.cfg.delayRetry) * time.Millisecond)
	p.cfg.delayRetry += IncDelayRetry
}

func (p *Ping) sendPacket(ipBytes []byte,
	id int,
	seq int,
) error {
	var (
		err error
		b   []byte
	)

	m := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   id,
			Seq:  seq,
			Data: []byte{0x0},
		},
	}

	b, err = m.Marshal(nil)
	if err != nil {
		return fmt.Errorf("error: marshal ICMP echo: %w", err)
	}

	err = p.conn.SetWriteDeadline(time.Now().Add(time.Duration(p.cfg.timeout) * time.Second))
	if err != nil {
		return fmt.Errorf("error: set ping write timeout: %w", err)
	}

	_, err = p.conn.WriteTo(b, &net.UDPAddr{
		IP:   ipBytes,
		Port: 33434,
	})
	if err != nil {
		return fmt.Errorf("error: ping: %w", err)
	}

	return nil
}

func (p *Ping) rcvPacket(done chan<- bool) error {
	resp := make([]byte, 1500)
	tries := 0

	for tries <= p.cfg.rcvTries {
		if err := p.conn.SetReadDeadline(time.Now().
			Add(time.Duration(p.cfg.timeout) * time.Second)); err != nil {
			return fmt.Errorf("error: set read deadline: %w", err)
		}

		n, _, err := p.conn.ReadFrom(resp)
		if err != nil {
			if tries >= p.cfg.rcvTries {
				var netErr *net.OpError
				if errors.As(err, &netErr) && netErr.Timeout() {
					done <- false

					return nil
				} else {
					return fmt.Errorf("error: ping: %w", err)
				}
			}

			tries++

			p.delayRetry()

			continue
		}

		var reply *icmp.Echo

		reply, err = p.isEchoReply(resp[:n])
		if err != nil {
			if tries >= p.cfg.rcvTries {
				return err
			}

			tries++

			p.delayRetry()

			continue
		} else {
			v, _ := p.awaitingSeqNums.Load(reply.ID)
			vs := v.(visitSeq)
			if !vs.visited {
				vs.visited = true

				done <- true

				break
			} else {
				if tries >= p.cfg.rcvTries {
					done <- false

					return nil
				}

				tries++

				p.delayRetry()

				continue
			}
		}
	}

	return nil
}

func (p *Ping) ping(ip string, id int, seq int) (bool, error) {
	var (
		err     error
		ok      bool
		ipBytes []byte
	)

	errChan := make(chan error)
	done := make(chan bool)

	ipBytes, err = IPStringToBytes(ip)
	if err != nil {
		return false, err
	}

	go func() {
		if err := p.sendPacket(ipBytes, id, seq); err != nil {
			errChan <- err
		}
	}()

	go func() {
		if err := p.rcvPacket(done); err != nil {
			errChan <- err
		}
	}()

	select {
	case err = <-errChan:
	case ok = <-done:
	}

	return ok, err
}

func (p *Ping) Ping(host string) (*Stats, error) {
	var (
		err error
		ip  string
		s   = new(Stats)
	)

	ctx, cancel := context.WithTimeout(context.Background(),
		time.Duration(p.cfg.timeout)*time.Second)
	defer cancel()

	ip, err = dns.HostToIP(ctx, host)
	if err != nil {
		return nil, err
	}

	switch {
	case p.cfg.privileged:
		p.conn, err = icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	default:
		p.conn, err = icmp.ListenPacket("udp4", "0.0.0.0")
	}

	if err != nil {
		return nil, fmt.Errorf("error: create socket: %w", err)
	}

	defer p.conn.Close()

	limit := make(chan struct{}, p.cfg.cping)
	errChan := make(chan error)
	tmp := make(chan *tmpResult)

	go func() {
		for range p.cfg.pingNum {
			limit <- struct{}{}

			go func() {
				start := time.Now()
				id := rand.IntN(MaxInt16)
				seq := rand.IntN(MaxInt16)

				p.awaitingSeqNums.Store(id, visitSeq{
					seq:     seq,
					visited: false,
				})

				ok, err := p.ping(ip, id, seq)
				if err != nil {
					errChan <- err
				} else {
					end := time.Since(start)

					tmp <- &tmpResult{
						valid: ok,
						rtt:   end,
					}
				}

				<-limit
			}()
		}
	}()

	for range p.cfg.pingNum {
		select {
		case err = <-errChan:
			return nil, err
		case t := <-tmp:
			s.NSent++

			if t.valid {
				s.NReceived++
				s.Rtt += t.rtt.Seconds()
			}
		}
	}

	s.PacketLoss = float64((s.NSent - s.NReceived) / p.cfg.pingNum)
	s.Up = s.NReceived > 0
	s.Rtt = math.Floor(s.Rtt*100) / 100

	var rdns string

	rdns, err = dns.IPToHost(ip)
	if err != nil {
		return nil, err
	}

	s.RDns = rdns

	return s, nil
}

func (p *Ping) isEchoReply(bytes []byte) (*icmp.Echo, error) {
	m, err := icmp.ParseMessage(1, bytes)
	if err != nil {
		return nil, fmt.Errorf("error: parse icmp message: %w", err)
	}

	b, ok := m.Body.(*icmp.Echo)
	if !ok {
		return nil, fmt.Errorf("error: body is not icmp echo")
	}

	return b, nil
}
