package ping

import (
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIPStringToBytes(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		err    error
		name   string
		input  string
		output net.IP
	}{
		{
			name:   "GivenIPStringToBytes_WhenReturnsErrInvalidIP_returnErrInvalidIP",
			input:  "1.1.1.1.1",
			output: nil,
			err:    ErrInvalidIP,
		},
		{
			name:   "GivenIPStringToBytes_WhenReturnsErr_returnErr",
			input:  "1.1.invalid.1",
			output: nil,
			err:    errors.New("error: resolve ip 1.1.invalid.1"),
		},
		{
			name:   "GivenIPStringToBytes_WhenIpParsed_returnSliceOfBytes",
			input:  "1.1.1.1",
			output: net.IPv4(1, 1, 1, 1).To4(),
			err:    nil,
		},
	}

	for _, row := range testCases {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()

			b, err := IPStringToIPv4(row.input)

			if row.err != nil {
				require.NotNil(t, err)
				require.Nil(t, b)

				assert.True(t, strings.Contains(err.Error(), row.err.Error()))
			} else {
				require.NotNil(t, b)
				require.Nil(t, err)

				assert.Equal(t, len(row.output), len(b))
				assert.Equal(t, row.output, b)
			}
		})
	}
}
