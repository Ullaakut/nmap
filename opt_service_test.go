package nmap

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestServiceDetection(t *testing.T) {
	baseOptions := nmapContainerOptions(t)

	tests := []struct {
		description string

		options []Option

		expectedArgs []string
		wantErr      require.ErrorAssertionFunc
	}{
		{
			description: "service detection",

			options: []Option{
				WithServiceInfo(),
			},

			expectedArgs: []string{
				"-sV",
			},
			wantErr: require.NoError,
		},
		{
			description: "service detection on all ports",

			options: []Option{
				WithVersionDetectionOnAllPorts(),
			},

			expectedArgs: []string{
				"--allports",
			},
			wantErr: require.NoError,
		},
		{
			description: "service detection custom intensity",

			options: []Option{
				WithVersionIntensity(1),
			},

			expectedArgs: []string{
				"--version-intensity",
				"1",
			},
			wantErr: require.NoError,
		},
		{
			description: "service detection custom intensity - should panic since not between 0 and 9",

			options: []Option{
				WithVersionIntensity(42),
			},

			wantErr: require.Error,
		},
		{
			description: "service detection light intensity",

			options: []Option{
				WithVersionLight(),
			},

			expectedArgs: []string{
				"--version-light",
			},
			wantErr: require.NoError,
		},
		{
			description: "service detection highest intensity",

			options: []Option{
				WithVersionAll(),
			},

			expectedArgs: []string{
				"--version-all",
			},
			wantErr: require.NoError,
		},
		{
			description: "service detection enable trace",

			options: []Option{
				WithVersionTrace(),
			},

			expectedArgs: []string{
				"--version-trace",
			},
			wantErr: require.NoError,
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			options := append([]Option{}, baseOptions...)
			options = append(options, test.options...)

			s, err := NewScanner(options...)
			test.wantErr(t, err)
			if err != nil {
				return
			}

			assertArgsSuffix(t, s.args, test.expectedArgs)
		})
	}
}
