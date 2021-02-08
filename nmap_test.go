package nmap

import (
	"context"
	"encoding/xml"
	"errors"
	"io/ioutil"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type testStreamer struct {
	Streamer
}

// Write is a function that handles the normal nmap stdout.
func (c *testStreamer) Write(d []byte) (int, error) {
	return len(d), nil
}

// Bytes returns scan result bytes.
func (c *testStreamer) Bytes() []byte {
	return []byte{}
}

func TestNmapNotInstalled(t *testing.T) {
	oldPath := os.Getenv("PATH")
	_ = os.Setenv("PATH", "")

	s, err := NewScanner()
	if err == nil {
		t.Error("expected NewScanner to fail if nmap is not found in $PATH")
	}

	if s != nil {
		t.Error("expected NewScanner to return a nil scanner if nmap is not found in $PATH")
	}

	_ = os.Setenv("PATH", oldPath)
}

func TestRun(t *testing.T) {
	nmapPath, err := exec.LookPath("nmap")
	if err != nil {
		panic("nmap is required to run those tests")
	}

	tests := []struct {
		description string

		options []Option

		testTimeout     bool
		compareWholeRun bool

		expectedResult   *Run
		expectedErr      bool
		expectedWarnings []string
	}{
		{
			description: "invalid binary path",

			options: []Option{
				WithTargets("0.0.0.0"),
				WithBinaryPath("/invalid"),
			},

			expectedErr:    true,
			expectedResult: nil,
		},
		{
			description: "output can't be parsed",

			options: []Option{
				WithTargets("0.0.0.0"),
				WithBinaryPath("echo"),
			},

			expectedErr:      true,
			expectedWarnings: []string{"EOF"},
		},
		{
			description: "context timeout",

			options: []Option{
				WithTargets("0.0.0.0/16"),
			},

			testTimeout: true,

			expectedErr: true,
		},
		{
			description: "scan localhost",

			options: []Option{
				WithTargets("localhost"),
				WithTimingTemplate(TimingFastest),
			},

			expectedResult: &Run{
				Args:    nmapPath + " -T5 -oX - localhost",
				Scanner: "nmap",
			},
		},
		{
			description: "scan invalid target",

			options: []Option{
				WithTimingTemplate(TimingFastest),
			},

			expectedWarnings: []string{"WARNING: No targets were specified, so 0 hosts scanned."},
			expectedResult: &Run{
				Scanner: "nmap",
				Args:    nmapPath + " -T5 -oX -",
			},
		},
		{
			description: "scan error resolving name",
			options: []Option{
				WithBinaryPath("tests/scripts/fake_nmap.sh"),
				WithCustomArguments("tests/xml/scan_error_resolving_name.xml"),
			},

			expectedErr: true,
			expectedResult: &Run{
				Scanner: "fake_nmap",
				Args:    "nmap test",
			},
		},
		{
			description: "scan unsupported error",
			options: []Option{
				WithBinaryPath("tests/scripts/fake_nmap.sh"),
				WithCustomArguments("tests/xml/scan_error_other.xml"),
			},

			expectedErr: true,
			expectedResult: &Run{
				Scanner: "fake_nmap",
				Args:    "nmap test",
			},
		},
		{
			description: "scan localhost with filters",
			options: []Option{
				WithBinaryPath("tests/scripts/fake_nmap.sh"),
				WithCustomArguments("tests/xml/scan_invalid_services.xml"),
				WithFilterHost(func(h Host) bool {
					return len(h.Ports) == 2
				}),
				WithFilterPort(func(p Port) bool {
					return p.Service.Product == "VALID"
				}),
				WithTimingTemplate(TimingFastest),
			},

			compareWholeRun: true,

			expectedResult: &Run{
				XMLName: xml.Name{Local: "nmaprun"},
				Args:    "nmap test",
				Scanner: "fake_nmap",
				Hosts: []Host{
					{
						Addresses: []Address{
							{
								Addr: "66.35.250.168",
							},
						},
						Ports: []Port{
							{
								ID: 80,
								State: State{
									State: "open",
								},
								Service: Service{
									Name:    "http",
									Product: "VALID",
								},
							},
							{
								ID: 443,
								State: State{
									State: "open",
								},
								Service: Service{
									Name:    "https",
									Product: "VALID",
								},
							},
						},
					},
				},
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

			s, err := NewScanner(test.options...)
			if err != nil {
				panic(err) // this is never supposed to err, as we are testing run and not new.
			}

			result, warns, err := s.Run()

			if !assert.Equal(t, test.expectedErr, err != nil) {
				return
			}

			assert.Equal(t, test.expectedWarnings, warns)

			if result == nil && test.expectedResult == nil {
				return
			} else if result == nil && test.expectedResult != nil {
				t.Error("expected non-nil result, got nil")
				return
			} else if result != nil && test.expectedResult == nil {
				t.Error("expected nil result, got non-nil")
				return
			}

			if test.compareWholeRun {
				result.rawXML = nil
				if !reflect.DeepEqual(test.expectedResult, result) {
					t.Errorf("expected result to be %+v, got %+v", test.expectedResult, result)
				}
			} else {
				if result.Args != test.expectedResult.Args {
					t.Errorf("expected args %s got %s", test.expectedResult.Args, result.Args)
				}

				if result.Scanner != test.expectedResult.Scanner {
					t.Errorf("expected scanner %s got %s", test.expectedResult.Scanner, result.Scanner)
				}
			}
		})
	}
}

func TestRunWithProgress(t *testing.T) {
	// Open and parse sample result for testing
	dat, err := ioutil.ReadFile("tests/xml/scan_base.xml")
	if err != nil {
		panic(err)
	}

	r, _ := Parse(dat)

	tests := []struct {
		description string

		options []Option

		compareWholeRun bool

		expectedResult   *Run
		expectedProgress []float32
		expectedErr      error
		expectedWarnings []string
	}{
		{
			description: "fake scan with slow output for progress streaming",
			options: []Option{
				WithBinaryPath("tests/scripts/fake_nmap_delay.sh"),
				WithCustomArguments("tests/xml/scan_base.xml"),
			},

			compareWholeRun:  true,
			expectedResult:   r,
			expectedProgress: []float32{56.66, 81.95, 87.84, 94.43, 97.76, 97.76},
			expectedErr:      nil,
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			s, err := NewScanner(test.options...)
			if err != nil {
				panic(err) // this is never supposed to err, as we are testing run and not new.
			}

			progress := make(chan float32, 5)
			result, _, err := s.RunWithProgress(progress)
			assert.Equal(t, test.expectedErr, err)
			if err != nil {
				return
			}

			// Test if channel data compares to given progress array
			var progressOutput []float32
			for n := range progress {
				progressOutput = append(progressOutput, n)
			}
			assert.Equal(t, test.expectedProgress, progressOutput)

			// Test if read output equals parsed xml file
			if test.compareWholeRun {
				assert.Equal(t, test.expectedResult.Hosts, result.Hosts)
			}
		})
	}
}

func TestRunWithStreamer(t *testing.T) {
	streamer := &testStreamer{}

	tests := []struct {
		description string

		options []Option

		expectedErr      error
		expectedWarnings []string
	}{
		{
			description: "fake scan with streaming",
			options: []Option{
				WithBinaryPath("tests/scripts/fake_nmap.sh"),
				WithCustomArguments("tests/xml/scan_base.xml"),
			},
			expectedErr:      nil,
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			s, err := NewScanner(test.options...)
			if err != nil {
				panic(err) // this is never supposed to err, as we are testing run and not new.
			}

			warnings, err := s.RunWithStreamer(streamer, "/tmp/nmap-stream-test")

			assert.Equal(t, test.expectedErr, err)

			assert.Equal(t, test.expectedWarnings, warnings)
		})
	}
}

func TestRunAsync(t *testing.T) {
	tests := []struct {
		description string

		options []Option

		testTimeout     bool
		compareWholeRun bool

		expectedResult      *Run
		expectedRunAsyncErr error
		expectedParseErr    error
		expectedWaitErr     bool
	}{
		{
			description: "invalid binary path",

			options: []Option{
				WithTargets("0.0.0.0"),
				WithBinaryPath("/invalid"),
			},

			expectedResult:      nil,
			expectedRunAsyncErr: errors.New("unable to execute asynchronous nmap run: fork/exec /invalid: no such file or directory"),
		},
		{
			description: "output can't be parsed",

			options: []Option{
				WithTargets("0.0.0.0"),
				WithBinaryPath("echo"),
			},

			expectedResult:   nil,
			expectedParseErr: errors.New("EOF"),
		},
		{
			description: "context timeout",

			options: []Option{
				WithTargets("0.0.0.0/16"),
			},

			testTimeout: true,

			expectedResult:  nil,
			expectedWaitErr: true,
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

			s, err := NewScanner(test.options...)
			if err != nil {
				panic(err) // this is never supposed to err, as we are testing run and not new.
			}

			err = s.RunAsync()
			assert.Equal(t, test.expectedRunAsyncErr, err)
			if err != nil {
				return
			}

			stdout := s.GetStdout()
			var content []byte
			go func() {
				for stdout.Scan() {
					content = stdout.Bytes()
				}
			}()

			err = s.Wait()
			if test.expectedWaitErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			if err != nil {
				return
			}

			result, err := Parse(content)
			assert.Equal(t, test.expectedParseErr, err)

			if result == nil && test.expectedResult == nil {
				return
			} else if result == nil && test.expectedResult != nil {
				t.Error("expected non-nil result, got nil")
				return
			} else if test.expectedResult == nil {
				return
			}

			if test.compareWholeRun {
				result.rawXML = nil
				if !reflect.DeepEqual(test.expectedResult, result) {
					t.Errorf("expected result to be %+v, got %+v", test.expectedResult, result)
				}
			} else {
				if result.Args != test.expectedResult.Args {
					t.Errorf("expected args %q got %q", test.expectedResult.Args, result.Args)
				}

				if result.Scanner != test.expectedResult.Scanner {
					t.Errorf("expected scanner %q got %q", test.expectedResult.Scanner, result.Scanner)
				}
			}
		})
	}
}

func TestTargetSpecification(t *testing.T) {
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
			description: "target exclusion",

			options: []Option{
				WithTargetExclusion("192.168.0.1,172.16.100.0/24"),
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
			s, err := NewScanner(test.options...)
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
			s, err := NewScanner(test.options...)
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
				"--scanflags",
				"11",
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
			s, err := NewScanner(test.options...)
			if err != nil {
				panic(err)
			}

			if !reflect.DeepEqual(s.args, test.expectedArgs) {
				t.Errorf("unexpected arguments, expected %s got %s", test.expectedArgs, s.args)
			}
		})
	}
}

func TestPortSpecAndScanOrder(t *testing.T) {
	tests := []struct {
		description string

		options []Option

		expectedPanic string
		expectedArgs  []string
	}{
		{
			description: "specify ports to scan",

			options: []Option{
				WithPorts("554", "8554"),
				WithPorts("80-81"),
			},

			expectedArgs: []string{
				"-p",
				"554,8554,80-81",
			},
		},
		{
			description: "exclude ports to scan",

			options: []Option{
				WithPortExclusions("554", "8554"),
			},

			expectedArgs: []string{
				"--exclude-ports",
				"554,8554",
			},
		},
		{
			description: "fast mode - scan fewer ports than the default scan",

			options: []Option{
				WithFastMode(),
			},

			expectedArgs: []string{
				"-F",
			},
		},
		{
			description: "consecutive port scanning",

			options: []Option{
				WithConsecutivePortScanning(),
			},

			expectedArgs: []string{
				"-r",
			},
		},
		{
			description: "scan most commonly open ports",

			options: []Option{
				WithMostCommonPorts(5),
			},

			expectedArgs: []string{
				"--top-ports",
				"5",
			},
		},
		{
			description: "scan most commonly open ports given a ratio - should be rounded to 0.4",

			options: []Option{
				WithPortRatio(0.42010101),
			},

			expectedArgs: []string{
				"--port-ratio",
				"0.4",
			},
		},
		{
			description: "scan most commonly open ports given a ratio - should be invalid and panic",

			options: []Option{
				WithPortRatio(2),
			},

			expectedPanic: "value given to nmap.WithPortRatio() should be between 0 and 1",
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

			s, err := NewScanner(test.options...)
			if err != nil {
				panic(err)
			}

			if !reflect.DeepEqual(s.args, test.expectedArgs) {
				t.Errorf("unexpected arguments, expected %s got %s", test.expectedArgs, s.args)
			}
		})
	}
}

func TestServiceDetection(t *testing.T) {
	tests := []struct {
		description string

		options []Option

		expectedPanic string
		expectedArgs  []string
	}{
		{
			description: "service detection",

			options: []Option{
				WithServiceInfo(),
			},

			expectedArgs: []string{
				"-sV",
			},
		},
		{
			description: "service detection custom intensity",

			options: []Option{
				WithVersionIntensity(1),
			},

			expectedArgs: []string{
				"--version-intensity",
				"1",
			},
		},
		{
			description: "service detection custom intensity - should panic since not between 0 and 9",

			options: []Option{
				WithVersionIntensity(42),
			},

			expectedPanic: "value given to nmap.WithVersionIntensity() should be between 0 and 9",
		},
		{
			description: "service detection light intensity",

			options: []Option{
				WithVersionLight(),
			},

			expectedArgs: []string{
				"--version-light",
			},
		},
		{
			description: "service detection highest intensity",

			options: []Option{
				WithVersionAll(),
			},

			expectedArgs: []string{
				"--version-all",
			},
		},
		{
			description: "service detection enable trace",

			options: []Option{
				WithVersionTrace(),
			},

			expectedArgs: []string{
				"--version-trace",
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

			s, err := NewScanner(test.options...)
			if err != nil {
				panic(err)
			}

			if !reflect.DeepEqual(s.args, test.expectedArgs) {
				t.Errorf("unexpected arguments, expected %s got %s", test.expectedArgs, s.args)
			}
		})
	}
}

func TestScriptScan(t *testing.T) {
	tests := []struct {
		description string

		targets       []string
		options       []Option
		unorderedArgs bool

		expectedArgs []string
	}{
		{
			description: "default script scan",

			options: []Option{
				WithDefaultScript(),
			},

			expectedArgs: []string{
				"-sC",
			},
		},
		{
			description: "custom script list",

			options: []Option{
				WithScripts("./scripts/", "/etc/nmap/nse/scripts"),
			},

			expectedArgs: []string{
				"--script=./scripts/,/etc/nmap/nse/scripts",
			},
		},
		{
			description: "script arguments",

			options: []Option{
				WithScriptArguments(map[string]string{
					"user":                  "foo",
					"pass":                  "\",{}=bar\"",
					"whois":                 "{whodb=nofollow+ripe}",
					"xmpp-info.server_name": "localhost",
					"vulns.showall":         "",
				}),
			},

			unorderedArgs: true,

			expectedArgs: []string{
				"--script-args=",
				"user=foo",
				"pass=\",{}=bar\"",
				"whois={whodb=nofollow+ripe}",
				"xmpp-info.server_name=localhost",
				"vulns.showall",
			},
		},
		{
			description: "script arguments file",

			options: []Option{
				WithScriptArgumentsFile("/script_args.txt"),
			},

			expectedArgs: []string{
				"--script-args-file=/script_args.txt",
			},
		},
		{
			description: "enable script trace",

			options: []Option{
				WithScriptTrace(),
			},

			expectedArgs: []string{
				"--script-trace",
			},
		},
		{
			description: "update script database",

			options: []Option{
				WithScriptUpdateDB(),
			},

			expectedArgs: []string{
				"--script-updatedb",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			s, err := NewScanner(test.options...)
			if err != nil {
				panic(err)
			}

			if test.unorderedArgs {
				for _, expectedArg := range test.expectedArgs {
					if !strings.Contains(s.args[0], expectedArg) {
						t.Errorf("missing argument %s in %v", expectedArg, s.args)
					}
				}
				return
			}

			if !reflect.DeepEqual(s.args, test.expectedArgs) {
				t.Errorf("unexpected arguments, expected %s got %s", test.expectedArgs, s.args)
			}
		})
	}
}

func TestOSDetection(t *testing.T) {
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
			s, err := NewScanner(test.options...)
			if err != nil {
				panic(err)
			}

			if !reflect.DeepEqual(s.args, test.expectedArgs) {
				t.Errorf("unexpected arguments, expected %s got %s", test.expectedArgs, s.args)
			}
		})
	}
}

func TestTimingAndPerformance(t *testing.T) {
	tests := []struct {
		description string

		options []Option

		expectedArgs []string
	}{
		{
			description: "set timing template",

			options: []Option{
				WithTimingTemplate(TimingAggressive),
			},

			expectedArgs: []string{
				"-T4",
			},
		},
		{
			description: "set stats every",

			options: []Option{
				WithStatsEvery("5s"),
			},

			expectedArgs: []string{
				"--stats-every",
				"5s",
			},
		},
		{
			description: "set min hostgroup",

			options: []Option{
				WithMinHostgroup(42),
			},

			expectedArgs: []string{
				"--min-hostgroup",
				"42",
			},
		},
		{
			description: "set max hostgroup",

			options: []Option{
				WithMaxHostgroup(42),
			},

			expectedArgs: []string{
				"--max-hostgroup",
				"42",
			},
		},
		{
			description: "set min parallelism",

			options: []Option{
				WithMinParallelism(42),
			},

			expectedArgs: []string{
				"--min-parallelism",
				"42",
			},
		},
		{
			description: "set max parallelism",

			options: []Option{
				WithMaxParallelism(42),
			},

			expectedArgs: []string{
				"--max-parallelism",
				"42",
			},
		},
		{
			description: "set min rtt-timeout",

			options: []Option{
				WithMinRTTTimeout(2 * time.Minute),
			},

			expectedArgs: []string{
				"--min-rtt-timeout",
				"120000ms",
			},
		},
		{
			description: "set max rtt-timeout",

			options: []Option{
				WithMaxRTTTimeout(8 * time.Hour),
			},

			expectedArgs: []string{
				"--max-rtt-timeout",
				"28800000ms",
			},
		},
		{
			description: "set initial rtt-timeout",

			options: []Option{
				WithInitialRTTTimeout(8 * time.Hour),
			},

			expectedArgs: []string{
				"--initial-rtt-timeout",
				"28800000ms",
			},
		},
		{
			description: "set max retries",

			options: []Option{
				WithMaxRetries(42),
			},

			expectedArgs: []string{
				"--max-retries",
				"42",
			},
		},
		{
			description: "set host timeout",

			options: []Option{
				WithHostTimeout(42 * time.Second),
			},

			expectedArgs: []string{
				"--host-timeout",
				"42000ms",
			},
		},
		{
			description: "set scan delay",

			options: []Option{
				WithScanDelay(42 * time.Millisecond),
			},

			expectedArgs: []string{
				"--scan-delay",
				"42ms",
			},
		},
		{
			description: "set max scan delay",

			options: []Option{
				WithMaxScanDelay(42 * time.Millisecond),
			},

			expectedArgs: []string{
				"--max-scan-delay",
				"42ms",
			},
		},
		{
			description: "set min rate",

			options: []Option{
				WithMinRate(42),
			},

			expectedArgs: []string{
				"--min-rate",
				"42",
			},
		},
		{
			description: "set max rate",

			options: []Option{
				WithMaxRate(42),
			},

			expectedArgs: []string{
				"--max-rate",
				"42",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			s, err := NewScanner(test.options...)
			if err != nil {
				panic(err)
			}

			if !reflect.DeepEqual(s.args, test.expectedArgs) {
				t.Errorf("unexpected arguments, expected %s got %s", test.expectedArgs, s.args)
			}
		})
	}
}

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
				WithSourcePort(4242),
			},

			expectedArgs: []string{
				"--source-port",
				"4242",
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

			s, err := NewScanner(test.options...)
			if err != nil {
				panic(err)
			}

			if !reflect.DeepEqual(s.args, test.expectedArgs) {
				t.Errorf("unexpected arguments, expected %s got %s", test.expectedArgs, s.args)
			}
		})
	}
}

func TestOutput(t *testing.T) {
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
			description: "enable interface listing",

			options: []Option{
				WithInterfaceList(),
			},

			expectedArgs: []string{
				"--iflist",
			},
		},
		{
			description: "enable interface listing",

			options: []Option{
				WithInterfaceList(),
			},

			expectedArgs: []string{
				"--iflist",
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
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			s, err := NewScanner(test.options...)
			if err != nil {
				panic(err)
			}

			if !reflect.DeepEqual(s.args, test.expectedArgs) {
				t.Errorf("unexpected arguments, expected %s got %s", test.expectedArgs, s.args)
			}
		})
	}
}

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
			s, err := NewScanner(test.options...)
			if err != nil {
				panic(err)
			}

			if !reflect.DeepEqual(s.args, test.expectedArgs) {
				t.Errorf("unexpected arguments, expected %s got %s", test.expectedArgs, s.args)
			}
		})
	}
}

func TestAnalyzeWarnings(t *testing.T) {
	tests := []struct {
		description string

		warnings []string

		expectedErr error
	}{
		{
			description: "Find no error warning",
			warnings: []string{"NoWarning", "NoWarning"},
			expectedErr: nil,
		},
		{
			description: "Find malloc error",
			warnings: []string{"   Malloc Failed! with "},
			expectedErr: ErrMallocFailed,
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			err := analyzeWarnings(test.warnings)

			assert.Equal(t, test.expectedErr, err)
		})
	}
}
