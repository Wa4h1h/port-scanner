package dns

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHostToIP(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		err    error
		name   string
		input  string
		output string
	}{
		{
			name:   "GivenHostToIP_WhenLookupHostReturnErr_returnErr",
			input:  "unknown",
			output: "",
			err:    errors.New("error: lookup host"),
		},
		{
			name:   "GivenHostToIP_WhenLookupHostReturnResults_returnIPString",
			input:  "localhost",
			output: "127.0.0.1",
			err:    nil,
		},
	}

	for _, row := range testCases {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()

			ip, err := HostToIP(context.Background(), row.input)

			if row.err != nil {
				require.NotNil(t, err)
				assert.True(t, strings.Contains(err.Error(), row.err.Error()))
			} else {
				require.Nil(t, err)
				assert.Equal(t, row.output, ip)
			}
		})
	}
}

func TestIPToHost(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		err    error
		name   string
		input  string
		output string
	}{
		{
			name:   "GivenIPToHost_WhenLookupAddrReturnErr_returnErr",
			input:  "unknown",
			output: "",
			err:    errors.New("error: reverse lookup addr"),
		},
		{
			name:   "GivenIPToHost_WhenLookupAddrReturnResults_returnHostString",
			input:  "127.0.0.1",
			output: "localhost",
			err:    nil,
		},
	}

	for _, row := range testCases {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()

			ip, err := IPToHost(row.input)

			if row.err != nil {
				require.NotNil(t, err)
				fmt.Println(err)
				assert.True(t, strings.Contains(err.Error(), row.err.Error()))
			} else {
				require.Nil(t, err)
				assert.Equal(t, row.output, ip)
			}
		})
	}
}
