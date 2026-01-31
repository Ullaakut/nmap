package nmap

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTargetSpecification(t *testing.T) {
	baseOptions := nmapContainerOptions(t)

	tests := []struct {
		description string

		options []Option

		expectedArgs []string
	}{
		{
			description: "custom arguments",

			options: []Option{
				WithTargets("0.0.0.0/24"),
				WithCustomArguments("--invalid-argument"),
			},

			expectedArgs: []string{
				"0.0.0.0/24",
				"--invalid-argument",
			},
		},
		{
			description: "set target",

			options: []Option{
				WithTargets("0.0.0.0/24"),
			},

			expectedArgs: []string{
				"0.0.0.0/24",
			},
		},
		{
			description: "set multiple targets",

			options: []Option{
				WithTargets("0.0.0.0", "192.168.1.1"),
			},

			expectedArgs: []string{
				"0.0.0.0",
				"192.168.1.1",
			},
		},
		{
			description: "set target from file",

			options: []Option{
				WithTargetInput("/targets.txt"),
			},

			expectedArgs: []string{
				"-iL",
				"/targets.txt",
			},
		},
		{
			description: "choose random targets",

			options: []Option{
				WithRandomTargets(4),
			},

			expectedArgs: []string{
				"-iR",
				"4",
			},
		},
		{
			description: "unique addresses",

			options: []Option{
				WithUnique(),
			},

			expectedArgs: []string{
				"--unique",
			},
		},
		{
			description: "target exclusion",

			options: []Option{
				WithTargetExclusions("192.168.0.1", "172.16.100.0/24"),
			},

			expectedArgs: []string{
				"--exclude",
				"192.168.0.1,172.16.100.0/24",
			},
		},
		{
			description: "target exclusion from file",

			options: []Option{
				WithTargetExclusionInput("/exclude_targets.txt"),
			},

			expectedArgs: []string{
				"--excludefile",
				"/exclude_targets.txt",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			options := append([]Option{}, baseOptions...)
			options = append(options, test.options...)

			s, err := NewScanner(options...)
			require.NoError(t, err)

			assertArgsSuffix(t, s.args, test.expectedArgs)
		})
	}
}
