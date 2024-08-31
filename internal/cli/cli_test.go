package cli

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//nolint:funlen
func TestCli_Run(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		err    error
		input  []string
		output *settings
		name   string
	}{
		{
			name:   "GivenRun_WhenHostMissing_PrintHostMissing",
			input:  []string{},
			output: nil,
			err:    ErrHostsMissing,
		},
		{
			name:  "GivenRun_WhenOnlyHostsProvided_ParseOnlyHosts",
			input: []string{"-hosts=127.0.0.1,google.com"},
			output: &settings{
				hosts:      "127.0.0.1,google.com",
				ports:      Ports,
				timeout:    DefaultTimeout,
				cscan:      DefaultCScan,
				tcp:        TCP,
				udp:        UDP,
				vanilla:    Vanilla,
				syn:        SYN,
				useDefault: UseDefaultSettings,
			},
			err: nil,
		},
		{
			name:  "GivenRun_WhenMoreThanOneFlagWasProvided_ParseFlags",
			input: []string{"-hosts=127.0.0.1,google.com", "-v", "-syn"},
			output: &settings{
				hosts:      "127.0.0.1,google.com",
				ports:      Ports,
				timeout:    DefaultTimeout,
				cscan:      DefaultCScan,
				tcp:        TCP,
				udp:        UDP,
				vanilla:    true,
				syn:        true,
				useDefault: UseDefaultSettings,
			},
			err: nil,
		},
	}

	for _, row := range testCases {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()

			c := NewCli()
			err := c.Run(row.input)

			if row.err != nil {
				require.NotNil(t, err)
				assert.Equal(t, row.err, err)
			} else {
				assert.Equal(t, row.output.hosts, c.s.hosts)
				assert.Equal(t, row.output.ports, c.s.ports)
				assert.Equal(t, row.output.timeout, c.s.timeout)
				assert.Equal(t, row.output.cscan, c.s.cscan)
				assert.Equal(t, row.output.tcp, c.s.tcp)
				assert.Equal(t, row.output.udp, c.s.udp)
				assert.Equal(t, row.output.vanilla, c.s.vanilla)
				assert.Equal(t, row.output.syn, c.s.syn)
				assert.Equal(t, row.output.useDefault, c.s.useDefault)
			}
		})
	}
}
