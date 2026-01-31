package nmap

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestTimingAndPerformance(t *testing.T) {
	baseOptions := nmapContainerOptions(t)

	tests := []struct {
		description string

		options []Option

		expectedArgs []string
		wantErr      require.ErrorAssertionFunc
	}{
		{
			description: "set timing template",

			options: []Option{
				WithTimingTemplate(TimingAggressive),
			},

			expectedArgs: []string{
				"-T4",
			},
			wantErr: require.NoError,
		},
		{
			description: "set min hostgroup",

			options: []Option{
				WithMinHostgroup(42),
			},

			expectedArgs: []string{
				"--min-hostgroup",
				"42",
			},
			wantErr: require.NoError,
		},
		{
			description: "set max hostgroup",

			options: []Option{
				WithMaxHostgroup(42),
			},

			expectedArgs: []string{
				"--max-hostgroup",
				"42",
			},
			wantErr: require.NoError,
		},
		{
			description: "set min parallelism",

			options: []Option{
				WithMinParallelism(42),
			},

			expectedArgs: []string{
				"--min-parallelism",
				"42",
			},
			wantErr: require.NoError,
		},
		{
			description: "set max parallelism",

			options: []Option{
				WithMaxParallelism(42),
			},

			expectedArgs: []string{
				"--max-parallelism",
				"42",
			},
			wantErr: require.NoError,
		},
		{
			description: "set min rtt-timeout",

			options: []Option{
				WithMinRTTTimeout(2 * time.Minute),
			},

			expectedArgs: []string{
				"--min-rtt-timeout",
				"2m",
			},
			wantErr: require.NoError,
		},
		{
			description: "set invalid rtt-timeout",

			options: []Option{
				WithMinRTTTimeout(-2 * time.Minute),
			},

			wantErr: require.Error,
		},
		{
			description: "set max rtt-timeout",

			options: []Option{
				WithMaxRTTTimeout(8 * time.Hour),
			},

			expectedArgs: []string{
				"--max-rtt-timeout",
				"8h",
			},
			wantErr: require.NoError,
		},
		{
			description: "set invalid max rtt-timeout",

			options: []Option{
				WithMaxRTTTimeout(-8 * time.Hour),
			},

			wantErr: require.Error,
		},
		{
			description: "set initial rtt-timeout",

			options: []Option{
				WithInitialRTTTimeout(8 * time.Hour),
			},

			expectedArgs: []string{
				"--initial-rtt-timeout",
				"8h",
			},
			wantErr: require.NoError,
		},
		{
			description: "set invalid initial rtt-timeout",

			options: []Option{
				WithInitialRTTTimeout(-8 * time.Hour),
			},

			wantErr: require.Error,
		},
		{
			description: "set max retries",

			options: []Option{
				WithMaxRetries(42),
			},

			expectedArgs: []string{
				"--max-retries",
				"42",
			},
			wantErr: require.NoError,
		},
		{
			description: "set host timeout",

			options: []Option{
				WithHostTimeout(42 * time.Second),
			},

			expectedArgs: []string{
				"--host-timeout",
				"42s",
			},
			wantErr: require.NoError,
		},
		{
			description: "set invalid host timeout",

			options: []Option{
				WithHostTimeout(-42 * time.Second),
			},

			wantErr: require.Error,
		},
		{
			description: "set scan delay",

			options: []Option{
				WithScanDelay(42 * time.Millisecond),
			},

			expectedArgs: []string{
				"--scan-delay",
				"42ms",
			},
			wantErr: require.NoError,
		},
		{
			description: "set invalid scan delay",

			options: []Option{
				WithScanDelay(-42 * time.Millisecond),
			},

			wantErr: require.Error,
		},
		{
			description: "set max scan delay",

			options: []Option{
				WithMaxScanDelay(42 * time.Millisecond),
			},

			expectedArgs: []string{
				"--max-scan-delay",
				"42ms",
			},
			wantErr: require.NoError,
		},
		{
			description: "set invalid max scan delay",

			options: []Option{
				WithMaxScanDelay(-42 * time.Millisecond),
			},

			wantErr: require.Error,
		},
		{
			description: "set min rate",

			options: []Option{
				WithMinRate(42),
			},

			expectedArgs: []string{
				"--min-rate",
				"42",
			},
			wantErr: require.NoError,
		},
		{
			description: "set max rate",

			options: []Option{
				WithMaxRate(42),
			},

			expectedArgs: []string{
				"--max-rate",
				"42",
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
