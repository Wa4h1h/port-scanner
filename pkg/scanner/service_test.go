package scanner

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPortToService(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name   string
		input  []string
		output []string
	}{
		{
			name:   "GivenPortToService_WhenPort/ProtoExists_returnServiceName",
			input:  []string{"80/tcp", "443/tcp", "22/tcp"},
			output: []string{"http", "https", "ssh"},
		},
		{
			name:   "GivenPortToService_WhenPort/ProtoDontExists_returnDescriptivePort",
			input:  []string{"50000/tcp", "50001/tcp", "50002/udp"},
			output: []string{"50000/tcp", "50001/tcp", "50002/udp"},
		},
	}

	for _, row := range testCases {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()

			for i, in := range row.input {
				out := PortToService(in)

				assert.Equal(t, row.output[i], out)
			}
		})
	}
}
