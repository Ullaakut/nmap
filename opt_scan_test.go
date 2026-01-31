package nmap

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestScanTechniques(t *testing.T) {
	baseOptions := nmapContainerOptions(t)

	tests := []struct {
		description string

		options []Option

		expectedArgs []string
	}{
		{
			description: "TCP SYN scan",

			options: []Option{
				WithSYNScan(),
			},

			expectedArgs: []string{
				"-sS",
			},
		},
		{
			description: "TCP Connect() scan",

			options: []Option{
				WithConnectScan(),
			},

			expectedArgs: []string{
				"-sT",
			},
		},
		{
			description: "TCP ACK scan",

			options: []Option{
				WithACKScan(),
			},

			expectedArgs: []string{
				"-sA",
			},
		},
		{
			description: "TCP Window scan",

			options: []Option{
				WithWindowScan(),
			},

			expectedArgs: []string{
				"-sW",
			},
		},
		{
			description: "Maimon scan",

			options: []Option{
				WithMaimonScan(),
			},

			expectedArgs: []string{
				"-sM",
			},
		},
		{
			description: "UDP scan",

			options: []Option{
				WithUDPScan(),
			},

			expectedArgs: []string{
				"-sU",
			},
		},
		{
			description: "TCP Null scan",

			options: []Option{
				WithTCPNullScan(),
			},

			expectedArgs: []string{
				"-sN",
			},
		},
		{
			description: "TCP FIN scan",

			options: []Option{
				WithTCPFINScan(),
			},

			expectedArgs: []string{
				"-sF",
			},
		},
		{
			description: "TCP Xmas scan",

			options: []Option{
				WithTCPXmasScan(),
			},

			expectedArgs: []string{
				"-sX",
			},
		},
		{
			description: "TCP custom scan flags",

			options: []Option{
				WithTCPScanFlags(FlagACK, FlagFIN, FlagNULL),
			},

			expectedArgs: []string{
				"--scanflags=ACKFIN",
			},
		},
		{
			description: "TCP scan flags ALL flags",

			options: []Option{
				WithTCPScanFlags(FlagNS, FlagCWR, FlagECE, FlagURG, FlagACK, FlagPSH, FlagRST, FlagSYN, FlagFIN, FlagNULL),
			},

			expectedArgs: []string{
				"--scanflags=NSCWRECEURGACKPSHRSTSYNFIN",
			},
		},
		{
			description: "idle scan through zombie host with probe port specified",

			options: []Option{
				WithIdleScan("192.168.1.1", 61436),
			},

			expectedArgs: []string{
				"-sI",
				"192.168.1.1:61436",
			},
		},
		{
			description: "idle scan through zombie host without probe port specified",

			options: []Option{
				WithIdleScan("192.168.1.1", 0),
			},

			expectedArgs: []string{
				"-sI",
				"192.168.1.1",
			},
		},
		{
			description: "SCTP INIT scan",

			options: []Option{
				WithSCTPInitScan(),
			},

			expectedArgs: []string{
				"-sY",
			},
		},
		{
			description: "SCTP COOKIE-ECHO scan",

			options: []Option{
				WithSCTPCookieEchoScan(),
			},

			expectedArgs: []string{
				"-sZ",
			},
		},
		{
			description: "IP protocol scan",

			options: []Option{
				WithIPProtocolScan(),
			},

			expectedArgs: []string{
				"-sO",
			},
		},
		{
			description: "FTP bounce scan",

			options: []Option{
				WithFTPBounceScan("192.168.0.254"),
			},

			expectedArgs: []string{
				"-b",
				"192.168.0.254",
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
