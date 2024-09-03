package ping

import "golang.org/x/net/icmp"

// make sure we conform to Pinger
var _ Pinger = &Ping{}

type Pinger interface {
	Ping(host string) (bool, error)
}

type Ping struct {
	conn         *icmp.PacketConn
	timeout      int
	readNumTries int
	privileged   bool
}
