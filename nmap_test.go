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

type TestStreamer struct {
	Streamer
}

// Write is a function that handles the normal nmap stdout.
func (c *TestStreamer) Write(d []byte) (int, error) {
	return len(d), nil
}

// Bytes returns scan result bytes.
func (c *TestStreamer) Bytes() []byte {
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

		options []func(*Scanner)

		testTimeout     bool
		compareWholeRun bool

		expectedResult   *Run
		expectedErr      bool
		expectedWarnings []string
	}{
		{
			description: "invalid binary path",

			options: []func(*Scanner){
				WithTargets("0.0.0.0"),
				WithBinaryPath("/invalid"),
			},

			expectedErr:    true,
			expectedResult: nil,
		},
		{
			description: "output can't be parsed",

			options: []func(*Scanner){
				WithTargets("0.0.0.0"),
				WithBinaryPath("echo"),
			},

			expectedErr:      true,
			expectedWarnings: []string{"EOF"},
		},
		{
			description: "context timeout",

			options: []func(*Scanner){
				WithTargets("0.0.0.0/16"),
			},

			testTimeout: true,

			expectedErr: true,
		},
		{
			description: "scan localhost",

			options: []func(*Scanner){
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

			options: []func(*Scanner){
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
			options: []func(*Scanner){
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
			options: []func(*Scanner){
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
			options: []func(*Scanner){
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

		options []func(*Scanner)

		compareWholeRun bool

		expectedResult   *Run
		expectedProgress []float32
		expectedErr      error
		expectedWarnings []string
	}{
		{
			description: "fake scan with slow output for progress streaming",
			options: []func(*Scanner){
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
	streamer := &TestStreamer{}

	tests := []struct {
		description string

		options []func(*Scanner)

		expectedErr      error
		expectedWarnings []string
	}{
		{
			description: "fake scan with streaming",
			options: []func(*Scanner){
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

		options []func(*Scanner)

		testTimeout     bool
		compareWholeRun bool

		expectedResult      *Run
		expectedRunAsyncErr error
		expectedParseErr    error
		expectedWaitErr     bool
	}{
		{
			description: "invalid binary path",

			options: []func(*Scanner){
				WithTargets("0.0.0.0"),
				WithBinaryPath("/invalid"),
			},

			expectedResult:      nil,
			expectedRunAsyncErr: errors.New("unable to execute asynchronous nmap run: fork/exec /invalid: no such file or directory"),
		},
		{
			description: "output can't be parsed",

			options: []func(*Scanner){
				WithTargets("0.0.0.0"),
				WithBinaryPath("echo"),
			},

			expectedResult:   nil,
			expectedParseErr: errors.New("EOF"),
		},
		{
			description: "context timeout",

			options: []func(*Scanner){
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

		options []func(*Scanner)

		expectedArgs []string
	}{
		{
			description: "custom arguments",

			options: []func(*Scanner){
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

			options: []func(*Scanner){
				WithTargets("0.0.0.0/24"),
			},

			expectedArgs: []string{
				"0.0.0.0/24",
			},
		},
		{
			description: "set multiple targets",

			options: []func(*Scanner){
				WithTargets("0.0.0.0", "192.168.1.1"),
			},

			expectedArgs: []string{
				"0.0.0.0",
				"192.168.1.1",
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
				WithSYNDiscovery(),
			},

			expectedArgs: []string{
				"-PS",
			},
		},
		{
			description: "TCP SYN packets for specific ports",

			options: []func(*Scanner){
				WithSYNDiscovery("443", "8443"),
			},

			expectedArgs: []string{
				"-PS443,8443",
			},
		},
		{
			description: "TCP ACK packets for all ports",

			options: []func(*Scanner){
				WithACKDiscovery(),
			},

			expectedArgs: []string{
				"-PA",
			},
		},
		{
			description: "TCP ACK packets for specific ports",

			options: []func(*Scanner){
				WithACKDiscovery("443", "8443"),
			},

			expectedArgs: []string{
				"-PA443,8443",
			},
		},
		{
			description: "UDP packets for all ports",

			options: []func(*Scanner){
				WithUDPDiscovery(),
			},

			expectedArgs: []string{
				"-PU",
			},
		},
		{
			description: "UDP packets for specific ports",

			options: []func(*Scanner){
				WithUDPDiscovery("443", "8443"),
			},

			expectedArgs: []string{
				"-PU443,8443",
			},
		},
		{
			description: "SCTP packets for all ports",

			options: []func(*Scanner){
				WithSCTPDiscovery(),
			},

			expectedArgs: []string{
				"-PY",
			},
		},
		{
			description: "SCTP packets for specific ports",

			options: []func(*Scanner){
				WithSCTPDiscovery("443", "8443"),
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
				WithIPProtocolPingDiscovery("1", "2", "4"),
			},

			expectedArgs: []string{
				"-PO1,2,4",
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
				WithCustomDNSServers("8.8.8.8", "8.8.4.4"),
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

		options []func(*Scanner)

		expectedPanic string
		expectedArgs  []string
	}{
		{
			description: "specify ports to scan",

			options: []func(*Scanner){
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

			options: []func(*Scanner){
				WithPortExclusions("554", "8554"),
			},

			expectedArgs: []string{
				"--exclude-ports",
				"554,8554",
			},
		},
		{
			description: "fast mode - scan fewer ports than the default scan",

			options: []func(*Scanner){
				WithFastMode(),
			},

			expectedArgs: []string{
				"-F",
			},
		},
		{
			description: "consecutive port scanning",

			options: []func(*Scanner){
				WithConsecutivePortScanning(),
			},

			expectedArgs: []string{
				"-r",
			},
		},
		{
			description: "scan most commonly open ports",

			options: []func(*Scanner){
				WithMostCommonPorts(5),
			},

			expectedArgs: []string{
				"--top-ports",
				"5",
			},
		},
		{
			description: "scan most commonly open ports given a ratio - should be rounded to 0.4",

			options: []func(*Scanner){
				WithPortRatio(0.42010101),
			},

			expectedArgs: []string{
				"--port-ratio",
				"0.4",
			},
		},
		{
			description: "scan most commonly open ports given a ratio - should be invalid and panic",

			options: []func(*Scanner){
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

		options []func(*Scanner)

		expectedPanic string
		expectedArgs  []string
	}{
		{
			description: "service detection",

			options: []func(*Scanner){
				WithServiceInfo(),
			},

			expectedArgs: []string{
				"-sV",
			},
		},
		{
			description: "service detection custom intensity",

			options: []func(*Scanner){
				WithVersionIntensity(1),
			},

			expectedArgs: []string{
				"--version-intensity",
				"1",
			},
		},
		{
			description: "service detection custom intensity - should panic since not between 0 and 9",

			options: []func(*Scanner){
				WithVersionIntensity(42),
			},

			expectedPanic: "value given to nmap.WithVersionIntensity() should be between 0 and 9",
		},
		{
			description: "service detection light intensity",

			options: []func(*Scanner){
				WithVersionLight(),
			},

			expectedArgs: []string{
				"--version-light",
			},
		},
		{
			description: "service detection highest intensity",

			options: []func(*Scanner){
				WithVersionAll(),
			},

			expectedArgs: []string{
				"--version-all",
			},
		},
		{
			description: "service detection enable trace",

			options: []func(*Scanner){
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
		options       []func(*Scanner)
		unorderedArgs bool

		expectedArgs []string
	}{
		{
			description: "default script scan",

			options: []func(*Scanner){
				WithDefaultScript(),
			},

			expectedArgs: []string{
				"-sC",
			},
		},
		{
			description: "custom script list",

			options: []func(*Scanner){
				WithScripts("./scripts/", "/etc/nmap/nse/scripts"),
			},

			expectedArgs: []string{
				"--script=./scripts/,/etc/nmap/nse/scripts",
			},
		},
		{
			description: "script arguments",

			options: []func(*Scanner){
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

			options: []func(*Scanner){
				WithScriptArgumentsFile("/script_args.txt"),
			},

			expectedArgs: []string{
				"--script-args-file=/script_args.txt",
			},
		},
		{
			description: "enable script trace",

			options: []func(*Scanner){
				WithScriptTrace(),
			},

			expectedArgs: []string{
				"--script-trace",
			},
		},
		{
			description: "update script database",

			options: []func(*Scanner){
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

		options []func(*Scanner)

		expectedArgs []string
	}{
		{
			description: "enable OS detection",

			options: []func(*Scanner){
				WithOSDetection(),
			},

			expectedArgs: []string{
				"-O",
			},
		},
		{
			description: "enable OS scan limit",

			options: []func(*Scanner){
				WithOSScanLimit(),
			},

			expectedArgs: []string{
				"--osscan-limit",
			},
		},
		{
			description: "enable OS scan guess",

			options: []func(*Scanner){
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

		options []func(*Scanner)

		expectedArgs []string
	}{
		{
			description: "set timing template",

			options: []func(*Scanner){
				WithTimingTemplate(TimingAggressive),
			},

			expectedArgs: []string{
				"-T4",
			},
		},
		{
			description: "set stats every",

			options: []func(*Scanner){
				WithStatsEvery("5s"),
			},

			expectedArgs: []string{
				"--stats-every",
				"5s",
			},
		},
		{
			description: "set min hostgroup",

			options: []func(*Scanner){
				WithMinHostgroup(42),
			},

			expectedArgs: []string{
				"--min-hostgroup",
				"42",
			},
		},
		{
			description: "set max hostgroup",

			options: []func(*Scanner){
				WithMaxHostgroup(42),
			},

			expectedArgs: []string{
				"--max-hostgroup",
				"42",
			},
		},
		{
			description: "set min parallelism",

			options: []func(*Scanner){
				WithMinParallelism(42),
			},

			expectedArgs: []string{
				"--min-parallelism",
				"42",
			},
		},
		{
			description: "set max parallelism",

			options: []func(*Scanner){
				WithMaxParallelism(42),
			},

			expectedArgs: []string{
				"--max-parallelism",
				"42",
			},
		},
		{
			description: "set min rtt-timeout",

			options: []func(*Scanner){
				WithMinRTTTimeout(2 * time.Minute),
			},

			expectedArgs: []string{
				"--min-rtt-timeout",
				"120000ms",
			},
		},
		{
			description: "set max rtt-timeout",

			options: []func(*Scanner){
				WithMaxRTTTimeout(8 * time.Hour),
			},

			expectedArgs: []string{
				"--max-rtt-timeout",
				"28800000ms",
			},
		},
		{
			description: "set initial rtt-timeout",

			options: []func(*Scanner){
				WithInitialRTTTimeout(8 * time.Hour),
			},

			expectedArgs: []string{
				"--initial-rtt-timeout",
				"28800000ms",
			},
		},
		{
			description: "set max retries",

			options: []func(*Scanner){
				WithMaxRetries(42),
			},

			expectedArgs: []string{
				"--max-retries",
				"42",
			},
		},
		{
			description: "set host timeout",

			options: []func(*Scanner){
				WithHostTimeout(42 * time.Second),
			},

			expectedArgs: []string{
				"--host-timeout",
				"42000ms",
			},
		},
		{
			description: "set scan delay",

			options: []func(*Scanner){
				WithScanDelay(42 * time.Millisecond),
			},

			expectedArgs: []string{
				"--scan-delay",
				"42ms",
			},
		},
		{
			description: "set max scan delay",

			options: []func(*Scanner){
				WithMaxScanDelay(42 * time.Millisecond),
			},

			expectedArgs: []string{
				"--max-scan-delay",
				"42ms",
			},
		},
		{
			description: "set min rate",

			options: []func(*Scanner){
				WithMinRate(42),
			},

			expectedArgs: []string{
				"--min-rate",
				"42",
			},
		},
		{
			description: "set max rate",

			options: []func(*Scanner){
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

		options []func(*Scanner)

		expectedPanic string
		expectedArgs  []string
	}{
		{
			description: "fragment packets",

			options: []func(*Scanner){
				WithFragmentPackets(),
			},

			expectedArgs: []string{
				"-f",
			},
		},
		{
			description: "custom fragment packet size",

			options: []func(*Scanner){
				WithMTU(42),
			},

			expectedArgs: []string{
				"--mtu",
				"42",
			},
		},
		{
			description: "enable decoys",

			options: []func(*Scanner){
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

			options: []func(*Scanner){
				WithSpoofIPAddress("192.168.1.1"),
			},

			expectedArgs: []string{
				"-S",
				"192.168.1.1",
			},
		},
		{
			description: "set interface",

			options: []func(*Scanner){
				WithInterface("eth0"),
			},

			expectedArgs: []string{
				"-e",
				"eth0",
			},
		},
		{
			description: "set source port",

			options: []func(*Scanner){
				WithSourcePort(4242),
			},

			expectedArgs: []string{
				"--source-port",
				"4242",
			},
		},
		{
			description: "set proxies",

			options: []func(*Scanner){
				WithProxies("4242", "8484"),
			},

			expectedArgs: []string{
				"--proxies",
				"4242,8484",
			},
		},
		{
			description: "set custom hex payload",

			options: []func(*Scanner){
				WithHexData("0x8b6c42"),
			},

			expectedArgs: []string{
				"--data",
				"0x8b6c42",
			},
		},
		{
			description: "set custom ascii payload",

			options: []func(*Scanner){
				WithASCIIData("pale brownish"),
			},

			expectedArgs: []string{
				"--data-string",
				"pale brownish",
			},
		},
		{
			description: "set custom random payload length",

			options: []func(*Scanner){
				WithDataLength(42),
			},

			expectedArgs: []string{
				"--data-length",
				"42",
			},
		},
		{
			description: "set custom IP options",

			options: []func(*Scanner){
				WithIPOptions("S 192.168.1.1 10.0.0.3"),
			},

			expectedArgs: []string{
				"--ip-options",
				"S 192.168.1.1 10.0.0.3",
			},
		},
		{
			description: "set custom TTL",

			options: []func(*Scanner){
				WithIPTimeToLive(254),
			},

			expectedArgs: []string{
				"--ttl",
				"254",
			},
		},
		{
			description: "set custom TTL - invalid value should panic",

			options: []func(*Scanner){
				WithIPTimeToLive(-254),
			},

			expectedPanic: "value given to nmap.WithIPTimeToLive() should be between 0 and 255",
		},
		{
			description: "spoof mac address",

			options: []func(*Scanner){
				WithSpoofMAC("08:67:47:0A:78:E4"),
			},

			expectedArgs: []string{
				"--spoof-mac",
				"08:67:47:0A:78:E4",
			},
		},
		{
			description: "send packets with bad checksum",

			options: []func(*Scanner){
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

		options []func(*Scanner)

		expectedArgs []string
	}{
		{
			description: "set verbosity",

			options: []func(*Scanner){
				WithVerbosity(5),
			},

			expectedArgs: []string{
				"-v5",
			},
		},
		{
			description: "set debugging",

			options: []func(*Scanner){
				WithDebugging(3),
			},

			expectedArgs: []string{
				"-d3",
			},
		},
		{
			description: "display reason",

			options: []func(*Scanner){
				WithReason(),
			},

			expectedArgs: []string{
				"--reason",
			},
		},
		{
			description: "show only open ports",

			options: []func(*Scanner){
				WithOpenOnly(),
			},

			expectedArgs: []string{
				"--open",
			},
		},
		{
			description: "enable packet trace",

			options: []func(*Scanner){
				WithPacketTrace(),
			},

			expectedArgs: []string{
				"--packet-trace",
			},
		},
		{
			description: "enable interface listing",

			options: []func(*Scanner){
				WithInterfaceList(),
			},

			expectedArgs: []string{
				"--iflist",
			},
		},
		{
			description: "enable interface listing",

			options: []func(*Scanner){
				WithInterfaceList(),
			},

			expectedArgs: []string{
				"--iflist",
			},
		},
		{
			description: "enable appending output",

			options: []func(*Scanner){
				WithAppendOutput(),
			},

			expectedArgs: []string{
				"--append-output",
			},
		},
		{
			description: "resume scan from file",

			options: []func(*Scanner){
				WithResumePreviousScan("/nmap_scan.xml"),
			},

			expectedArgs: []string{
				"--resume",
				"/nmap_scan.xml",
			},
		},
		{
			description: "use stylesheet from file",

			options: []func(*Scanner){
				WithStylesheet("/nmap_stylesheet.xsl"),
			},

			expectedArgs: []string{
				"--stylesheet",
				"/nmap_stylesheet.xsl",
			},
		},
		{
			description: "use stylesheet from file",

			options: []func(*Scanner){
				WithStylesheet("/nmap_stylesheet.xsl"),
			},

			expectedArgs: []string{
				"--stylesheet",
				"/nmap_stylesheet.xsl",
			},
		},
		{
			description: "use default nmap stylesheet",

			options: []func(*Scanner){
				WithWebXML(),
			},

			expectedArgs: []string{
				"--webxml",
			},
		},
		{
			description: "disable stylesheets",

			options: []func(*Scanner){
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

		options []func(*Scanner)

		expectedArgs []string
	}{
		{
			description: "enable ipv6 scanning",

			options: []func(*Scanner){
				WithIPv6Scanning(),
			},

			expectedArgs: []string{
				"-6",
			},
		},
		{
			description: "enable aggressive scanning",

			options: []func(*Scanner){
				WithAggressiveScan(),
			},

			expectedArgs: []string{
				"-A",
			},
		},
		{
			description: "set data dir",

			options: []func(*Scanner){
				WithDataDir("/etc/nmap/data"),
			},

			expectedArgs: []string{
				"--datadir",
				"/etc/nmap/data",
			},
		},
		{
			description: "send packets over ethernet",

			options: []func(*Scanner){
				WithSendEthernet(),
			},

			expectedArgs: []string{
				"--send-eth",
			},
		},
		{
			description: "send packets over IP",

			options: []func(*Scanner){
				WithSendIP(),
			},

			expectedArgs: []string{
				"--send-ip",
			},
		},
		{
			description: "assume user is privileged",

			options: []func(*Scanner){
				WithPrivileged(),
			},

			expectedArgs: []string{
				"--privileged",
			},
		},
		{
			description: "assume user is unprivileged",

			options: []func(*Scanner){
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
			warnings: []string{"NoWaring", "NoWarning"},
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