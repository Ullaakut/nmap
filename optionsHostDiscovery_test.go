package nmap

import (
	"context"
	"reflect"
	"testing"
)

func TestHostDiscovery(t *testing.T) {
	tests := []struct {
		description string

		options []Option

		expectedArgs []string
	}{
		{
			description: "list targets to scan",

			options: []Option{
				WithListScan(),
			},

			expectedArgs: []string{
				"-sL",
			},
		},
		{
			description: "ping scan - disable port scan",

			options: []Option{
				WithPingScan(),
			},

			expectedArgs: []string{
				"-sn",
			},
		},
		{
			description: "skip host discovery",

			options: []Option{
				WithSkipHostDiscovery(),
			},

			expectedArgs: []string{
				"-Pn",
			},
		},
		{
			description: "TCP SYN packets for all ports",

			options: []Option{
				WithSYNDiscovery(),
			},

			expectedArgs: []string{
				"-PS",
			},
		},
		{
			description: "TCP SYN packets for specific ports",

			options: []Option{
				WithSYNDiscovery("443", "8443"),
			},

			expectedArgs: []string{
				"-PS443,8443",
			},
		},
		{
			description: "TCP ACK packets for all ports",

			options: []Option{
				WithACKDiscovery(),
			},

			expectedArgs: []string{
				"-PA",
			},
		},
		{
			description: "TCP ACK packets for specific ports",

			options: []Option{
				WithACKDiscovery("443", "8443"),
			},

			expectedArgs: []string{
				"-PA443,8443",
			},
		},
		{
			description: "UDP packets for all ports",

			options: []Option{
				WithUDPDiscovery(),
			},

			expectedArgs: []string{
				"-PU",
			},
		},
		{
			description: "UDP packets for specific ports",

			options: []Option{
				WithUDPDiscovery("443", "8443"),
			},

			expectedArgs: []string{
				"-PU443,8443",
			},
		},
		{
			description: "SCTP packets for all ports",

			options: []Option{
				WithSCTPDiscovery(),
			},

			expectedArgs: []string{
				"-PY",
			},
		},
		{
			description: "SCTP packets for specific ports",

			options: []Option{
				WithSCTPDiscovery("443", "8443"),
			},

			expectedArgs: []string{
				"-PY443,8443",
			},
		},
		{
			description: "ICMP echo request discovery probes",

			options: []Option{
				WithICMPEchoDiscovery(),
			},

			expectedArgs: []string{
				"-PE",
			},
		},
		{
			description: "ICMP Timestamp request discovery probes",

			options: []Option{
				WithICMPTimestampDiscovery(),
			},

			expectedArgs: []string{
				"-PP",
			},
		},
		{
			description: "ICMP NetMask request discovery probes",

			options: []Option{
				WithICMPNetMaskDiscovery(),
			},

			expectedArgs: []string{
				"-PM",
			},
		},
		{
			description: "IP protocol ping",

			options: []Option{
				WithIPProtocolPingDiscovery("1", "2", "4"),
			},

			expectedArgs: []string{
				"-PO1,2,4",
			},
		},
		{
			description: "disable DNS resolution during discovery",

			options: []Option{
				WithDisabledDNSResolution(),
			},

			expectedArgs: []string{
				"-n",
			},
		},
		{
			description: "enforce DNS resolution during discovery",

			options: []Option{
				WithForcedDNSResolution(),
			},

			expectedArgs: []string{
				"-R",
			},
		},
		{
			description: "custom DNS server",

			options: []Option{
				WithCustomDNSServers("8.8.8.8", "8.8.4.4"),
			},

			expectedArgs: []string{
				"--dns-servers",
				"8.8.8.8,8.8.4.4",
			},
		},
		{
			description: "use system DNS",

			options: []Option{
				WithSystemDNS(),
			},

			expectedArgs: []string{
				"--system-dns",
			},
		},
		{
			description: "traceroute",

			options: []Option{
				WithTraceRoute(),
			},

			expectedArgs: []string{
				"--traceroute",
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
