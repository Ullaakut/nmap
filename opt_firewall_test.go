package nmap

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFirewallAndIDSEvasionAndSpoofing(t *testing.T) {
	baseOptions := nmapContainerOptions(t)

	tests := []struct {
		description string

		options []Option

		expectedArgs []string
		wantErr      require.ErrorAssertionFunc
	}{
		{
			description: "fragment packets",

			options: []Option{
				WithFragmentPackets(),
			},

			expectedArgs: []string{
				"-f",
			},
			wantErr: require.NoError,
		},
		{
			description: "custom fragment packet size",

			options: []Option{
				WithMTU(42),
			},

			expectedArgs: []string{
				"--mtu",
				"42",
			},
			wantErr: require.NoError,
		},
		{
			description: "enable decoys",

			options: []Option{
				WithDecoys(
					"192.168.1.1",
					"192.168.1.2",
					"192.168.1.3",
					"192.168.1.4",
					"192.168.1.5",
					"192.168.1.6",
					"ME",
					"192.168.1.8",
				),
			},

			expectedArgs: []string{
				"-D",
				"192.168.1.1,192.168.1.2,192.168.1.3,192.168.1.4,192.168.1.5,192.168.1.6,ME,192.168.1.8",
			},
			wantErr: require.NoError,
		},
		{
			description: "spoof IP address",

			options: []Option{
				WithSpoofIPAddress("192.168.1.1"),
			},

			expectedArgs: []string{
				"-S",
				"192.168.1.1",
			},
			wantErr: require.NoError,
		},
		{
			description: "set interface",

			options: []Option{
				WithInterface("eth0"),
			},

			expectedArgs: []string{
				"-e",
				"eth0",
			},
			wantErr: require.NoError,
		},
		{
			description: "set source port",

			options: []Option{
				WithSourcePort(65535),
			},

			expectedArgs: []string{
				"--source-port",
				"65535",
			},
			wantErr: require.NoError,
		},
		{
			description: "set proxies",

			options: []Option{
				WithProxies("4242", "8484"),
			},

			expectedArgs: []string{
				"--proxies",
				"4242,8484",
			},
			wantErr: require.NoError,
		},
		{
			description: "set custom hex payload",

			options: []Option{
				WithHexData("0x8b6c42"),
			},

			expectedArgs: []string{
				"--data",
				"0x8b6c42",
			},
			wantErr: require.NoError,
		},
		{
			description: "set custom ascii payload",

			options: []Option{
				WithASCIIData("pale brownish"),
			},

			expectedArgs: []string{
				"--data-string",
				"pale brownish",
			},
			wantErr: require.NoError,
		},
		{
			description: "set custom random payload length",

			options: []Option{
				WithDataLength(42),
			},

			expectedArgs: []string{
				"--data-length",
				"42",
			},
			wantErr: require.NoError,
		},
		{
			description: "set custom IP options",

			options: []Option{
				WithIPOptions("S 192.168.1.1 10.0.0.3"),
			},

			expectedArgs: []string{
				"--ip-options",
				"S 192.168.1.1 10.0.0.3",
			},
			wantErr: require.NoError,
		},
		{
			description: "set custom TTL",

			options: []Option{
				WithIPTimeToLive(254),
			},

			expectedArgs: []string{
				"--ttl",
				"254",
			},
			wantErr: require.NoError,
		},
		{
			description: "set custom TTL - invalid value should error",

			options: []Option{
				WithIPTimeToLive(-254),
			},

			wantErr: require.Error,
		},
		{
			description: "spoof mac address",

			options: []Option{
				WithSpoofMAC("08:67:47:0A:78:E4"),
			},

			expectedArgs: []string{
				"--spoof-mac",
				"08:67:47:0A:78:E4",
			},
			wantErr: require.NoError,
		},
		{
			description: "send packets with bad checksum",

			options: []Option{
				WithBadSum(),
			},

			expectedArgs: []string{
				"--badsum",
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
