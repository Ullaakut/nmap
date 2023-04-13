package nmap

import (
	"context"
	"reflect"
	"testing"
)

func TestMiscellaneous(t *testing.T) {
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
