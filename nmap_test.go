package nmap

import (
	"context"
	"reflect"
	"testing"
	"time"
)

func TestRun(t *testing.T) {
	tests := []struct {
		description string
		options     []func(*Scanner)

		testTimeout bool

		expectedResult   *Run
		expectedErrorStr string
	}{
		{
			description: "no-target",
			options:     nil,

			expectedResult:   nil,
			expectedErrorStr: "WARNING: No targets were specified, so 0 hosts scanned.\n",
		},
		{
			description: "invalid binary path",
			options: []func(*Scanner){
				WithBinaryPath("/invalid"),
			},

			expectedResult:   nil,
			expectedErrorStr: "nmap scan failed: fork/exec /invalid: no such file or directory",
		},
		{
			description: "context timeout",
			options: []func(*Scanner){
				WithTarget("0.0.0.0/16"),
			},

			testTimeout: true,

			expectedResult:   nil,
			expectedErrorStr: "nmap scan timed out",
		},
		{
			description: "scan localhost",
			options: []func(*Scanner){
				WithTarget("localhost"),
			},

			expectedResult: &Run{
				Args:    "/usr/local/bin/nmap -oX - localhost",
				Scanner: "nmap",
			},
		},
		{
			description: "scan localhost with filters",
			options: []func(*Scanner){
				WithTarget("localhost"),
				WithFilterHost(func(Host) bool {
					return true
				}),
				WithFilterPort(func(Port) bool {
					return true
				}),
			},

			expectedResult: &Run{
				Args:    "/usr/local/bin/nmap -oX - localhost",
				Scanner: "nmap",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			if test.testTimeout {
				ctx, cancel := context.WithTimeout(context.Background(), 99*time.Hour)
				test.options = append(test.options, WithContext(ctx))

				go (func() {
					// Cancel context to force timeout
					defer cancel()
					time.Sleep(1 * time.Millisecond)
				})()
			}

			s, err := New(test.options...)
			if err != nil {
				panic(err) // this is never supposed to err, as we are testing run and not new.
			}

			result, err := s.Run()
			if err == nil {
				if test.expectedErrorStr != "" {
					t.Errorf("expected error %s got nil", test.expectedErrorStr)
				}
			} else if err.Error() != test.expectedErrorStr {
				t.Errorf("expected error %q got %q", test.expectedErrorStr, err.Error())
			}

			if result == nil && test.expectedResult == nil {
				return
			} else if result == nil && test.expectedResult != nil {
				t.Error("expected non-nil result, got nil")
				return
			} else if result != nil && test.expectedResult == nil {
				t.Error("expected nil result, got non-nil")
				return
			}

			if result.Args != test.expectedResult.Args {
				t.Errorf("expected args %s got %s", test.expectedResult.Args, result.Args)
			}

			if result.Scanner != test.expectedResult.Scanner {
				t.Errorf("expected scanner %s got %s", test.expectedResult.Scanner, result.Scanner)
			}
		})
	}
}

func TestTargetSpecification(t *testing.T) {
	tests := []struct {
		description string

		options []func(*Scanner)

		expectedArgs []string
	}{
		{
			description: "custom arguments",

			options: []func(*Scanner){
				WithCustomArguments("--invalid-argument"),
			},

			expectedArgs: []string{
				"--invalid-argument",
			},
		},
		{
			description: "set target",

			options: []func(*Scanner){
				WithTarget("0.0.0.0/24"),
			},

			expectedArgs: []string{
				"0.0.0.0/24",
			},
		},
		{
			description: "set target from file",

			options: []func(*Scanner){
				WithTargetInput("/targets.txt"),
			},

			expectedArgs: []string{
				"-iL",
				"/targets.txt",
			},
		},
		{
			description: "choose random targets",

			options: []func(*Scanner){
				WithRandomTargets(4),
			},

			expectedArgs: []string{
				"-iR",
				"4",
			},
		},
		{
			description: "target exclusion",

			options: []func(*Scanner){
				WithTargetExclusion("192.168.0.1,172.16.100.0/24"),
			},

			expectedArgs: []string{
				"--exclude",
				"192.168.0.1,172.16.100.0/24",
			},
		},
		{
			description: "target exclusion from file",

			options: []func(*Scanner){
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
			s, err := New(test.options...)
			if err != nil {
				panic(err)
			}

			if !reflect.DeepEqual(s.args, test.expectedArgs) {
				t.Errorf("unexpected arguments, expected %s got %s", test.expectedArgs, s.args)
			}
		})
	}
}

func TestHostDiscovery(t *testing.T) {
	tests := []struct {
		description string

		options []func(*Scanner)

		expectedArgs []string
	}{
		{
			description: "list targets to scan",

			options: []func(*Scanner){
				WithListScan(),
			},

			expectedArgs: []string{
				"-sL",
			},
		},
		{
			description: "ping scan - disable port scan",

			options: []func(*Scanner){
				WithPingScan(),
			},

			expectedArgs: []string{
				"-sn",
			},
		},
		{
			description: "skip host discovery",

			options: []func(*Scanner){
				WithSkipHostDiscovery(),
			},

			expectedArgs: []string{
				"-Pn",
			},
		},
		{
			description: "TCP SYN packets for all ports",

			options: []func(*Scanner){
				WithSYNDiscovery(""),
			},

			expectedArgs: []string{
				"-PS",
			},
		},
		{
			description: "TCP SYN packets for specific ports",

			options: []func(*Scanner){
				WithSYNDiscovery("443,8443"),
			},

			expectedArgs: []string{
				"-PS443,8443",
			},
		},
		{
			description: "TCP ACK packets for all ports",

			options: []func(*Scanner){
				WithACKDiscovery(""),
			},

			expectedArgs: []string{
				"-PA",
			},
		},
		{
			description: "TCP ACK packets for specific ports",

			options: []func(*Scanner){
				WithACKDiscovery("443,8443"),
			},

			expectedArgs: []string{
				"-PA443,8443",
			},
		},
		{
			description: "UDP packets for all ports",

			options: []func(*Scanner){
				WithUDPDiscovery(""),
			},

			expectedArgs: []string{
				"-PU",
			},
		},
		{
			description: "UDP packets for specific ports",

			options: []func(*Scanner){
				WithUDPDiscovery("443,8443"),
			},

			expectedArgs: []string{
				"-PU443,8443",
			},
		},
		{
			description: "SCTP packets for all ports",

			options: []func(*Scanner){
				WithSCTPDiscovery(""),
			},

			expectedArgs: []string{
				"-PY",
			},
		},
		{
			description: "SCTP packets for specific ports",

			options: []func(*Scanner){
				WithSCTPDiscovery("443,8443"),
			},

			expectedArgs: []string{
				"-PY443,8443",
			},
		},
		{
			description: "ICMP echo request discovery probes",

			options: []func(*Scanner){
				WithICMPEchoDiscovery(),
			},

			expectedArgs: []string{
				"-PE",
			},
		},
		{
			description: "ICMP Timestamp request discovery probes",

			options: []func(*Scanner){
				WithICMPTimestampDiscovery(),
			},

			expectedArgs: []string{
				"-PP",
			},
		},
		{
			description: "ICMP NetMask request discovery probes",

			options: []func(*Scanner){
				WithICMPNetMaskDiscovery(),
			},

			expectedArgs: []string{
				"-PM",
			},
		},
		{
			description: "IP protocol ping",

			options: []func(*Scanner){
				WithIPProtocolPingDiscovery("1,2,4"),
			},

			expectedArgs: []string{
				"-P01,2,4",
			},
		},
		{
			description: "disable DNS resolution during discovery",

			options: []func(*Scanner){
				WithDisabledDNSResolution(),
			},

			expectedArgs: []string{
				"-n",
			},
		},
		{
			description: "enforce DNS resolution during discovery",

			options: []func(*Scanner){
				WithForcedDNSResolution(),
			},

			expectedArgs: []string{
				"-R",
			},
		},
		{
			description: "custom DNS server",

			options: []func(*Scanner){
				WithCustomDNSServers("8.8.8.8,8.8.4.4"),
			},

			expectedArgs: []string{
				"--dns-servers",
				"8.8.8.8,8.8.4.4",
			},
		},
		{
			description: "use system DNS",

			options: []func(*Scanner){
				WithSystemDNS(),
			},

			expectedArgs: []string{
				"--system-dns",
			},
		},
		{
			description: "traceroute",

			options: []func(*Scanner){
				WithTraceRoute(),
			},

			expectedArgs: []string{
				"--traceroutes",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			s, err := New(test.options...)
			if err != nil {
				panic(err)
			}

			if !reflect.DeepEqual(s.args, test.expectedArgs) {
				t.Errorf("unexpected arguments, expected %s got %s", test.expectedArgs, s.args)
			}
		})
	}
}

func TestScanTechniques(t *testing.T) {
	tests := []struct {
		description string

		options []func(*Scanner)

		expectedArgs []string
	}{
		{
			description: "TCP SYN scan",

			options: []func(*Scanner){
				WithSYNScan(),
			},

			expectedArgs: []string{
				"-sS",
			},
		},
		{
			description: "TCP Connect() scan",

			options: []func(*Scanner){
				WithConnectScan(),
			},

			expectedArgs: []string{
				"-sT",
			},
		},
		{
			description: "TCP ACK scan",

			options: []func(*Scanner){
				WithACKScan(),
			},

			expectedArgs: []string{
				"-sA",
			},
		},
		{
			description: "TCP Window scan",

			options: []func(*Scanner){
				WithWindowScan(),
			},

			expectedArgs: []string{
				"-sW",
			},
		},
		{
			description: "Maimon scan",

			options: []func(*Scanner){
				WithMaimonScan(),
			},

			expectedArgs: []string{
				"-sM",
			},
		},
		{
			description: "UDP scan",

			options: []func(*Scanner){
				WithUDPScan(),
			},

			expectedArgs: []string{
				"-sU",
			},
		},
		{
			description: "TCP Null scan",

			options: []func(*Scanner){
				WithTCPNullScan(),
			},

			expectedArgs: []string{
				"-sN",
			},
		},
		{
			description: "TCP FIN scan",

			options: []func(*Scanner){
				WithTCPFINScan(),
			},

			expectedArgs: []string{
				"-sF",
			},
		},
		{
			description: "TCP Xmas scan",

			options: []func(*Scanner){
				WithTCPXmasScan(),
			},

			expectedArgs: []string{
				"-sX",
			},
		},
		{
			description: "TCP custom scan flags",

			options: []func(*Scanner){
				WithTCPScanFlags(FlagACK, FlagFIN, FlagNULL),
			},

			expectedArgs: []string{
				"--scanflags",
				"11",
			},
		},
		{
			description: "idle scan through zombie host with probe port specified",

			options: []func(*Scanner){
				WithIdleScan("192.168.1.1", 61436),
			},

			expectedArgs: []string{
				"-sI",
				"192.168.1.1:61436",
			},
		},
		{
			description: "idle scan through zombie host without probe port specified",

			options: []func(*Scanner){
				WithIdleScan("192.168.1.1", 0),
			},

			expectedArgs: []string{
				"-sI",
				"192.168.1.1",
			},
		},
		{
			description: "SCTP INIT scan",

			options: []func(*Scanner){
				WithSCTPInitScan(),
			},

			expectedArgs: []string{
				"-sY",
			},
		},
		{
			description: "SCTP COOKIE-ECHO scan",

			options: []func(*Scanner){
				WithSCTPCookieEchoScan(),
			},

			expectedArgs: []string{
				"-sZ",
			},
		},
		{
			description: "IP protocol scan",

			options: []func(*Scanner){
				WithIPProtocolScan(),
			},

			expectedArgs: []string{
				"-sO",
			},
		},
		{
			description: "FTP bounce scan",

			options: []func(*Scanner){
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
			s, err := New(test.options...)
			if err != nil {
				panic(err)
			}

			if !reflect.DeepEqual(s.args, test.expectedArgs) {
				t.Errorf("unexpected arguments, expected %s got %s", test.expectedArgs, s.args)
			}
		})
	}
}

// func TestPortSpecAndScanOrder(t *testing.T) {
// 	tests := []struct {
// 		description string

// 		options []func(*Scanner)

// 		expectedArgs []string
// 	}{
// 		{
// 			description: "",

// 			options: []func(*Scanner){
// 				WithXXX(),
// 			},

// 			expectedArgs: []string{
// 				"--xxx",
// 			},
// 		},
// 	}

// 	for _, test := range tests {
// 		t.Run(test.description, func(t *testing.T) {
// 			s, err := New(test.options...)
// 			if err != nil {
// 				panic(err)
// 			}

// 			if !reflect.DeepEqual(s.args, test.expectedArgs) {
// 				t.Errorf("unexpected arguments, expected %s got %s", test.expectedArgs, s.args)
// 			}
// 		})
// 	}
// }

// func TestServiceDetection(t *testing.T) {
// 	tests := []struct {
// 		description string

// 		options []func(*Scanner)

// 		expectedArgs []string
// 	}{
// 		{
// 			description: "",

// 			options: []func(*Scanner){
// 				WithXXX(),
// 			},

// 			expectedArgs: []string{
// 				"--xxx",
// 			},
// 		},
// 	}

// 	for _, test := range tests {
// 		t.Run(test.description, func(t *testing.T) {
// 			s, err := New(test.options...)
// 			if err != nil {
// 				panic(err)
// 			}

// 			if !reflect.DeepEqual(s.args, test.expectedArgs) {
// 				t.Errorf("unexpected arguments, expected %s got %s", test.expectedArgs, s.args)
// 			}
// 		})
// 	}
// }

// func TestScriptScan(t *testing.T) {
// 	tests := []struct {
// 		description string

// 		options []func(*Scanner)

// 		expectedArgs []string
// 	}{
// 		{
// 			description: "",

// 			options: []func(*Scanner){
// 				WithXXX(),
// 			},

// 			expectedArgs: []string{
// 				"--xxx",
// 			},
// 		},
// 	}

// 	for _, test := range tests {
// 		t.Run(test.description, func(t *testing.T) {
// 			s, err := New(test.options...)
// 			if err != nil {
// 				panic(err)
// 			}

// 			if !reflect.DeepEqual(s.args, test.expectedArgs) {
// 				t.Errorf("unexpected arguments, expected %s got %s", test.expectedArgs, s.args)
// 			}
// 		})
// 	}
// }

// func TestOSDetection(t *testing.T) {
// 	tests := []struct {
// 		description string

// 		options []func(*Scanner)

// 		expectedArgs []string
// 	}{
// 		{
// 			description: "",

// 			options: []func(*Scanner){
// 				WithXXX(),
// 			},

// 			expectedArgs: []string{
// 				"--xxx",
// 			},
// 		},
// 	}

// 	for _, test := range tests {
// 		t.Run(test.description, func(t *testing.T) {
// 			s, err := New(test.options...)
// 			if err != nil {
// 				panic(err)
// 			}

// 			if !reflect.DeepEqual(s.args, test.expectedArgs) {
// 				t.Errorf("unexpected arguments, expected %s got %s", test.expectedArgs, s.args)
// 			}
// 		})
// 	}
// }

// func TestTimingAndPerformance(t *testing.T) {
// 	tests := []struct {
// 		description string

// 		options []func(*Scanner)

// 		expectedArgs []string
// 	}{
// 		{
// 			description: "",

// 			options: []func(*Scanner){
// 				WithXXX(),
// 			},

// 			expectedArgs: []string{
// 				"--xxx",
// 			},
// 		},
// 	}

// 	for _, test := range tests {
// 		t.Run(test.description, func(t *testing.T) {
// 			s, err := New(test.options...)
// 			if err != nil {
// 				panic(err)
// 			}

// 			if !reflect.DeepEqual(s.args, test.expectedArgs) {
// 				t.Errorf("unexpected arguments, expected %s got %s", test.expectedArgs, s.args)
// 			}
// 		})
// 	}
// }

// func TestFirewallAndIDSEvasionAndSpoofing(t *testing.T) {
// 	tests := []struct {
// 		description string

// 		options []func(*Scanner)

// 		expectedArgs []string
// 	}{
// 		{
// 			description: "",

// 			options: []func(*Scanner){
// 				WithXXX(),
// 			},

// 			expectedArgs: []string{
// 				"--xxx",
// 			},
// 		},
// 	}

// 	for _, test := range tests {
// 		t.Run(test.description, func(t *testing.T) {
// 			s, err := New(test.options...)
// 			if err != nil {
// 				panic(err)
// 			}

// 			if !reflect.DeepEqual(s.args, test.expectedArgs) {
// 				t.Errorf("unexpected arguments, expected %s got %s", test.expectedArgs, s.args)
// 			}
// 		})
// 	}
// }

// func TestOutput(t *testing.T) {
// 	tests := []struct {
// 		description string

// 		options []func(*Scanner)

// 		expectedArgs []string
// 	}{
// 		{
// 			description: "",

// 			options: []func(*Scanner){
// 				WithXXX(),
// 			},

// 			expectedArgs: []string{
// 				"--xxx",
// 			},
// 		},
// 	}

// 	for _, test := range tests {
// 		t.Run(test.description, func(t *testing.T) {
// 			s, err := New(test.options...)
// 			if err != nil {
// 				panic(err)
// 			}

// 			if !reflect.DeepEqual(s.args, test.expectedArgs) {
// 				t.Errorf("unexpected arguments, expected %s got %s", test.expectedArgs, s.args)
// 			}
// 		})
// 	}
// }

// func TestMiscellaneous(t *testing.T) {
// 	tests := []struct {
// 		description string

// 		options []func(*Scanner)

// 		expectedArgs []string
// 	}{
// 		{
// 			description: "",

// 			options: []func(*Scanner){
// 				WithXXX(),
// 			},

// 			expectedArgs: []string{
// 				"--xxx",
// 			},
// 		},
// 	}

// 	for _, test := range tests {
// 		t.Run(test.description, func(t *testing.T) {
// 			s, err := New(test.options...)
// 			if err != nil {
// 				panic(err)
// 			}

// 			if !reflect.DeepEqual(s.args, test.expectedArgs) {
// 				t.Errorf("unexpected arguments, expected %s got %s", test.expectedArgs, s.args)
// 			}
// 		})
// 	}
// }
