package ping

import (
	"sync"
	"time"

	"golang.org/x/net/icmp"
)

// make sure we conform to Pinger.
var _ Pinger = &Ping{}

type Pinger interface {
	Ping(host string) (*Stats, error)
}

var DefaultConfig = Config{
	Timeout:    DefaultTimeout,
	PingNum:    DefaultNumPings,
	Privileged: Privileged,
	RcvTries:   DefaultRcvTries,
	Cping:      DefaultCPing,
	DelayRetry: DefaultDelayRetry,
}

type Config struct {
	// Timeout socket read/write timeout
	Timeout int
	// RcvTries is the number of time to read before the read op
	// is considered as a failed read
	RcvTries int
	// PingNum is the number of ICMP echo request to send
	PingNum int
	// Cping number of concurrent ping
	Cping int
	// Privileged is set to true, then raw socket will be used as the underlying socket type
	// otherwise, then dgram socket will be used as the underlying socket type
	Privileged bool
	// DelayRetry tells how much time(milliseconds) to wait before
	// retrying a read icmp message op
	DelayRetry int
}

type visitSeq struct {
	visited bool
	seq     int
}

type Ping struct {
	conn            *icmp.PacketConn
	cfg             *Config
	awaitingSeqNums sync.Map
}

type tmpResult struct {
	rtt   time.Duration
	valid bool
}

type Stats struct {
	// reverse dns record
	RDns string
	// avg rtt
	Rtt float64
	// number of sent packet
	NSent int
	// number of received packet
	NReceived int
	// percentage of lost packet
	PacketLoss float64
	// host is up
	Up bool
}
