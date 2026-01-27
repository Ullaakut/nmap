package nmap

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOSDetection(t *testing.T) {
	baseOptions := nmapContainerOptions(t)

	tests := []struct {
		description string

		options []Option

		expectedArgs []string
	}{
		{
			description: "enable OS detection",

			options: []Option{
				WithOSDetection(),
			},

			expectedArgs: []string{
				"-O",
			},
		},
		{
			description: "enable OS scan limit",

			options: []Option{
				WithOSScanLimit(),
			},

			expectedArgs: []string{
				"--osscan-limit",
			},
		},
		{
			description: "enable OS scan guess",

			options: []Option{
				WithOSScanGuess(),
			},

			expectedArgs: []string{
				"--osscan-guess",
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
