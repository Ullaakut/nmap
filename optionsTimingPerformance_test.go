package nmap

import (
	"context"
	"reflect"
	"testing"
	"time"
)

func TestTimingAndPerformance(t *testing.T) {
	tests := []struct {
		description string

		options []Option

		expectedArgs []string
	}{
		{
			description: "set timing template",

			options: []Option{
				WithTimingTemplate(TimingAggressive),
			},

			expectedArgs: []string{
				"-T4",
			},
		},
		{
			description: "set stats every",

			options: []Option{
				WithStatsEvery("5s"),
			},

			expectedArgs: []string{
				"--stats-every",
				"5s",
			},
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
		},
		{
			description: "set min rtt-timeout",

			options: []Option{
				WithMinRTTTimeout(2 * time.Minute),
			},

			expectedArgs: []string{
				"--min-rtt-timeout",
				"120000ms",
			},
		},
		{
			description: "set max rtt-timeout",

			options: []Option{
				WithMaxRTTTimeout(8 * time.Hour),
			},

			expectedArgs: []string{
				"--max-rtt-timeout",
				"28800000ms",
			},
		},
		{
			description: "set initial rtt-timeout",

			options: []Option{
				WithInitialRTTTimeout(8 * time.Hour),
			},

			expectedArgs: []string{
				"--initial-rtt-timeout",
				"28800000ms",
			},
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
		},
		{
			description: "set host timeout",

			options: []Option{
				WithHostTimeout(42 * time.Second),
			},

			expectedArgs: []string{
				"--host-timeout",
				"42000ms",
			},
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
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			s, err := NewScanner(context.TODO(), test.options...)
			if err != nil {
				panic(err)
			}

			if !reflect.DeepEqual(s.args, test.expectedArgs) {
				t.Errorf("unexpected arguments, expected %s got %s", test.expectedArgs, s.args)
			}
		})
	}
}
