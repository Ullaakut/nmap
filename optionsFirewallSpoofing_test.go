package nmap

import (
	"context"
	"reflect"
	"testing"
)

func TestFirewallAndIDSEvasionAndSpoofing(t *testing.T) {
	tests := []struct {
		description string

		options []Option

		expectedPanic string
		expectedArgs  []string
	}{
		{
			description: "fragment packets",

			options: []Option{
				WithFragmentPackets(),
			},

			expectedArgs: []string{
				"-f",
			},
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
		},
		{
			description: "set custom TTL - invalid value should panic",

			options: []Option{
				WithIPTimeToLive(-254),
			},

			expectedPanic: "value given to nmap.WithIPTimeToLive() should be between 0 and 255",
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
		},
		{
			description: "send packets with bad checksum",

			options: []Option{
				WithBadSum(),
			},

			expectedArgs: []string{
				"--badsum",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			if test.expectedPanic != "" {
				defer func() {
					recoveredMessage := recover()

					if recoveredMessage != test.expectedPanic {
						t.Errorf("expected panic message to be %q but got %q", test.expectedPanic, recoveredMessage)
					}
				}()
			}

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
