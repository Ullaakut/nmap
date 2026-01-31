package nmap

import (
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMiscellaneous(t *testing.T) {
	baseOptions := nmapContainerOptions(t)

	tests := []struct {
		description string

		options []Option

		expectedArgs []string
	}{
		{
			description: "enable ipv6 scanning",

			options: []Option{
				WithIPv6Scanning(),
			},

			expectedArgs: []string{
				"-6",
			},
		},
		{
			description: "enable aggressive scanning",

			options: []Option{
				WithAggressiveScan(),
			},

			expectedArgs: []string{
				"-A",
			},
		},
		{
			description: "set data dir",

			options: []Option{
				WithDataDir("/etc/nmap/data"),
			},

			expectedArgs: []string{
				"--datadir",
				"/etc/nmap/data",
			},
		},
		{
			description: "send packets over ethernet",

			options: []Option{
				WithSendEthernet(),
			},

			expectedArgs: []string{
				"--send-eth",
			},
		},
		{
			description: "send packets over IP",

			options: []Option{
				WithSendIP(),
			},

			expectedArgs: []string{
				"--send-ip",
			},
		},
		{
			description: "assume user is privileged",

			options: []Option{
				WithPrivileged(),
			},

			expectedArgs: []string{
				"--privileged",
			},
		},
		{
			description: "assume user is unprivileged",

			options: []Option{
				WithUnprivileged(),
			},

			expectedArgs: []string{
				"--unprivileged",
			},
		},
		{
			description: "nmap output path",

			options: []Option{
				WithNmapOutput("/tmp/nmap-output"),
			},

			expectedArgs: []string{
				"-oN", "/tmp/nmap-output",
			},
		},
		{
			description: "nmap grep output",

			options: []Option{
				WithGrepOutput("/tmp/nmap-output"),
			},

			expectedArgs: []string{
				"-oG", "/tmp/nmap-output",
			},
		},
		{
			description: "nmap grep output",

			options: []Option{
				WithCustomSysProcAttr(func(*syscall.SysProcAttr) {}),
			},

			expectedArgs: []string{
				// No specific args to check for this one.
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
