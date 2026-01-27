package nmap

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPortSpecAndScanOrder(t *testing.T) {
	baseOptions := nmapContainerOptions(t)

	tests := []struct {
		description string

		options []Option

		expectedArgs []string
		wantErr      require.ErrorAssertionFunc
	}{
		{
			description: "specify ports to scan",

			options: []Option{
				WithPorts("554", "8554"),
				WithPorts("80-81"),
			},

			expectedArgs: []string{
				"-p",
				"554,8554,80-81",
			},
			wantErr: require.NoError,
		},
		{
			description: "exclude ports to scan",

			options: []Option{
				WithPortExclusions("554", "8554"),
			},

			expectedArgs: []string{
				"--exclude-ports",
				"554,8554",
			},
			wantErr: require.NoError,
		},
		{
			description: "fast mode - scan fewer ports than the default scan",

			options: []Option{
				WithFastMode(),
			},

			expectedArgs: []string{
				"-F",
			},
			wantErr: require.NoError,
		},
		{
			description: "consecutive port scanning",

			options: []Option{
				WithConsecutivePortScanning(),
			},

			expectedArgs: []string{
				"-r",
			},
			wantErr: require.NoError,
		},
		{
			description: "scan most commonly open ports",

			options: []Option{
				WithMostCommonPorts(5),
			},

			expectedArgs: []string{
				"--top-ports",
				"5",
			},
			wantErr: require.NoError,
		},
		{
			description: "scan most commonly open ports given a ratio - should be rounded to 0.4",

			options: []Option{
				WithPortRatio(0.42010101),
			},

			expectedArgs: []string{
				"--port-ratio",
				"0.4",
			},
			wantErr: require.NoError,
		},
		{
			description: "scan most commonly open ports given a ratio - should be invalid and panic",

			options: []Option{
				WithPortRatio(2),
			},

			wantErr: require.Error,
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
