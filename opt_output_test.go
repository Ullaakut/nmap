package nmap

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOutput(t *testing.T) {
	baseOptions := nmapContainerOptions(t)

	tests := []struct {
		description string

		options []Option

		expectedArgs []string
	}{
		{
			description: "set verbosity",

			options: []Option{
				WithVerbosity(5),
			},

			expectedArgs: []string{
				"-v5",
			},
		},
		{
			description: "set debugging",

			options: []Option{
				WithDebugging(3),
			},

			expectedArgs: []string{
				"-d3",
			},
		},
		{
			description: "display reason",

			options: []Option{
				WithReason(),
			},

			expectedArgs: []string{
				"--reason",
			},
		},
		{
			description: "show only open ports",

			options: []Option{
				WithOpenOnly(),
			},

			expectedArgs: []string{
				"--open",
			},
		},
		{
			description: "enable packet trace",

			options: []Option{
				WithPacketTrace(),
			},

			expectedArgs: []string{
				"--packet-trace",
			},
		},
		{
			description: "enable appending output",

			options: []Option{
				WithAppendOutput(),
			},

			expectedArgs: []string{
				"--append-output",
			},
		},
		{
			description: "resume scan from file",

			options: []Option{
				WithResumePreviousScan("/nmap_scan.xml"),
			},

			expectedArgs: []string{
				"--resume",
				"/nmap_scan.xml",
			},
		},
		{
			description: "use stylesheet from file",

			options: []Option{
				WithStylesheet("/nmap_stylesheet.xsl"),
			},

			expectedArgs: []string{
				"--stylesheet",
				"/nmap_stylesheet.xsl",
			},
		},
		{
			description: "use stylesheet from file",

			options: []Option{
				WithStylesheet("/nmap_stylesheet.xsl"),
			},

			expectedArgs: []string{
				"--stylesheet",
				"/nmap_stylesheet.xsl",
			},
		},
		{
			description: "use default nmap stylesheet",

			options: []Option{
				WithWebXML(),
			},

			expectedArgs: []string{
				"--webxml",
			},
		},
		{
			description: "disable stylesheets",

			options: []Option{
				WithNoStylesheet(),
			},

			expectedArgs: []string{
				"--no-stylesheet",
			},
		},
		{
			description: "disable interactions",

			options: []Option{
				WithNonInteractive(),
			},

			expectedArgs: []string{
				"--noninteractive",
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
