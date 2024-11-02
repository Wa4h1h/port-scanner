package ping

import (
	"errors"
	"strings"
	"testing"

	"github.com/Wa4h1h/port-scanner/pkg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPing_Ping(t *testing.T) {
	testCases := []struct {
		name   string
		pinger Pinger
		input  string
		output *Stats
		err    error
	}{
		{
			name:   "HostToIPReturnsErr_returnErr",
			pinger: NewPinger(nil),
			input:  "unknown",
			output: nil,
			err:    errors.New("lookup unknown: no such host"),
		},
		{
			name:   "WithPrivilegedEnabledWithoutRoot_returnErr",
			pinger: NewPinger(nil, WithPrivileged(true)),
			input:  "127.0.0.1",
			output: nil,
			err:    errors.New("socket: operation not permitted"),
		},
		{
			name:   "Ping3times_returnResults",
			pinger: NewPinger(nil),
			input:  "localhost",
			output: &Stats{
				DnsInfo: &dns.DNSInfo{
					IP: "127.0.0.1",
				},
				NSent:     3,
				NReceived: 3,
				Up:        true,
			},
			err: nil,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			stats, err := testCase.pinger.Ping(testCase.input)

			if testCase.output != nil {
				require.Nil(t, err)
				require.NotNil(t, stats)

				assert.Equal(t, testCase.output.NSent, stats.NSent)
				assert.Equal(t, testCase.output.NReceived, stats.NReceived)
				assert.Equal(t, testCase.output.Up, stats.Up)
				assert.Equal(t, testCase.output.DnsInfo.IP, stats.DnsInfo.IP)

			} else {
				require.NotNil(t, err)
				require.Nil(t, stats)

				assert.True(t, strings.Contains(err.Error(),
					testCase.err.Error()))
			}
		})
	}
}
