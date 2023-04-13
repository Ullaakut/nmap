package nmap

import (
	"bytes"
	"context"
	"encoding/xml"
	"io/ioutil"
	"os"
	"os/exec"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type testStreamer struct{}

// Write is a function that handles the normal nmap stdout.
func (c *testStreamer) Write(d []byte) (int, error) {
	return len(d), nil
}

func TestNmapNotInstalled(t *testing.T) {
	oldPath := os.Getenv("PATH")
	_ = os.Setenv("PATH", "")

	s, err := NewScanner(context.TODO())
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

			expectedErr:      true,
			expectedWarnings: []string{},
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

			expectedErr:      true,
			expectedWarnings: []string{},
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

			expectedWarnings: []string{},
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

			expectedErr:      true,
			expectedWarnings: []string{},
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

			expectedErr:      true,
			expectedWarnings: []string{},
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

			compareWholeRun:  true,
			expectedWarnings: []string{},

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
			ctx := context.Background()
			if test.testTimeout {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(context.Background(), 99*time.Hour)

				go (func() {
					// Cancel context to force timeout
					defer cancel()
					time.Sleep(1 * time.Millisecond)
				})()
			}

			s, err := NewScanner(ctx, test.options...)
			if err != nil {
				panic(err) // this is never supposed to err, as we are testing run and not new.
			}

			result, warns, err := s.Run()

			if !assert.Equal(t, test.expectedErr, err != nil) {
				return
			}

			assert.Equal(t, test.expectedWarnings, *warns)

			if test.expectedResult == nil {
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

	var r = &Run{}
	_ = Parse(dat, r)

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
			expectedProgress: []float32{3.22, 56.66, 77.02, 81.95, 86.79, 87.84},
			expectedErr:      nil,
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			s, err := NewScanner(context.TODO(), test.options...)
			if err != nil {
				panic(err) // this is never supposed to err, as we are testing run and not new.
			}

			progress := make(chan float32, 5)
			result, _, err := s.Progress(progress).Run()
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
			expectedWarnings: []string{},
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			s, err := NewScanner(context.TODO(), test.options...)
			if err != nil {
				panic(err) // this is never supposed to err, as we are testing run and not new.
			}

			_, warnings, err := s.Streamer(streamer).Run()

			assert.Equal(t, test.expectedErr, err)

			assert.Equal(t, test.expectedWarnings, *warnings)
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
		expectedRunAsyncErr bool
		expectedWaitErr     bool
	}{
		{
			description: "invalid binary path",

			options: []Option{
				WithTargets("0.0.0.0"),
				WithBinaryPath("/invalid"),
			},

			expectedRunAsyncErr: true,
		},
		{
			description: "output can't be parsed",

			options: []Option{
				WithTargets("0.0.0.0"),
				WithBinaryPath("echo"),
			},

			expectedWaitErr: true,
		},
		{
			description: "context timeout",

			options: []Option{
				WithTargets("0.0.0.0/16"),
			},

			testTimeout: true,

			expectedWaitErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			ctx := context.Background()
			if test.testTimeout {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(context.Background(), 99*time.Hour)

				go (func() {
					// Cancel context to force timeout
					defer cancel()
					time.Sleep(10 * time.Millisecond)
				})()
			}

			s, err := NewScanner(ctx, test.options...)
			if err != nil {
				panic(err) // this is never supposed to err, as we are testing run and not new.
			}

			done := make(chan error)
			result, _, err := s.Async(done).Run()
			if test.expectedRunAsyncErr {
				assert.NotNil(t, err)
			}
			if err != nil {
				return
			}

			err = <-done
			if test.expectedWaitErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			if err != nil {
				return
			}

			if test.expectedResult == nil {
				return
			}

			if test.compareWholeRun {
				result.rawXML = nil
				if !reflect.DeepEqual(test.expectedResult, result) {
					t.Errorf("expected result to be %+v, got %+v", test.expectedResult, result)
				}
			}
		})
	}
}

func TestCheckStdErr(t *testing.T) {
	tests := []struct {
		description string
		stderr      string
		warnings    []string
		expectedErr error
	}{
		{
			description: "Find no error warning",
			stderr:      " NoWarning  \nNoWarning  ",
			warnings:    []string{"NoWarning", "NoWarning"},
			expectedErr: nil,
		},
		{
			description: "Find malloc error",
			stderr:      "   Malloc Failed! with ",
			warnings:    []string{"Malloc Failed! with"},
			expectedErr: ErrMallocFailed,
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			buf := bytes.Buffer{}
			_, _ = buf.Write([]byte(test.stderr))
			var warnings []string
			err := checkStdErr(&buf, &warnings)

			assert.Equal(t, test.expectedErr, err)
			assert.True(t, reflect.DeepEqual(test.warnings, warnings))
		})
	}
}
