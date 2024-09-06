package ping

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type pingOutput struct {
	err    error
	status bool
}

func TestPing_Ping(t *testing.T) {
	t.Parallel()

	p := NewPinger(1, 1, false)

	testCases := []struct {
		output pingOutput
		name   string
		input  string
	}{
		{
			name:  "GivenPing_WhenHostToIPReturnsErr_returnErr",
			input: "invalid",
			output: pingOutput{
				status: false,
				err:    errors.New("error: lookup host"),
			},
		}, {
			name:  "GivenPing_WhenPingLocalhostReturnsTrue_returnTrue",
			input: "localhost",
			output: pingOutput{
				status: true,
				err:    nil,
			},
		}, {
			name:  "GivenPing_WhenPingRemoteHostReturnsTrue_returnTrue",
			input: "google.com",
			output: pingOutput{
				status: true,
				err:    nil,
			},
		},
	}

	for _, row := range testCases {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()

			status, err := p.Ping(row.input)

			if row.output.err != nil {
				require.NotNil(t, err)
				assert.False(t, status)
				assert.True(t, strings.Contains(err.Error(),
					row.output.err.Error()))
			} else {
				require.Nil(t, err)
				assert.True(t, status)
			}
		})
	}
}
