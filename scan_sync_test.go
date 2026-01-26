package nmap

import (
	"context"
	"encoding/xml"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestRun(t *testing.T) {
	tests := []struct {
		description string

		options []Option

		testTimeout     bool
		compareWholeRun bool
		useContainer    bool

		expectedResult *Run
		wantErr        require.ErrorAssertionFunc
	}{
		{
			description: "scan localhost",

			options: []Option{
				WithTargets("localhost"),
				WithTimingTemplate(TimingFastest),
			},
			useContainer: true,

			expectedResult: &Run{
				Scanner: "nmap",
				Args:    "nmap -T5 -oX - localhost",
			},
			wantErr: require.NoError,
		},
		{
			description: "missing target",

			options: []Option{
				WithTimingTemplate(TimingFastest),
			},
			useContainer: true,

			expectedResult: &Run{
				Scanner: "nmap",
				Args:    "nmap -T5 -oX -",
				Stats:   Stats{Hosts: HostStats{Total: 0}},
			},
			wantErr: require.NoError,
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
				Hosts: []Host{{
					Addresses: []Address{{Addr: "66.35.250.168"}},
					Ports: []Port{
						{ID: 80, State: State{State: "open"}, Service: Service{Name: "http", Product: "VALID"}},
						{ID: 443, State: State{State: "open"}, Service: Service{Name: "https", Product: "VALID"}},
					},
				},
				},
			},
			wantErr: require.NoError,
		},
		{
			description: "invalid binary path",

			options: []Option{
				WithTargets("0.0.0.0"),
				WithBinaryPath("/invalid"),
			},

			wantErr: require.Error,
		},
		{
			description: "output can't be parsed",

			options: []Option{
				WithTargets("0.0.0.0"),
				WithBinaryPath("echo"),
			},

			wantErr: require.Error,
		},
		{
			description: "context timeout",

			options: []Option{
				WithTargets("0.0.0.0/16"),
			},

			testTimeout:  true,
			useContainer: true,

			wantErr: require.Error,
		},
		{
			description: "scan error resolving name",
			options: []Option{
				WithBinaryPath("tests/scripts/fake_nmap.sh"),
				WithCustomArguments("tests/xml/scan_error_resolving_name.xml"),
			},

			expectedResult: &Run{
				Scanner: "fake_nmap",
				Args:    "nmap test",
			},
			wantErr: require.Error,
		},
		{
			description: "scan unsupported error",
			options: []Option{
				WithBinaryPath("tests/scripts/fake_nmap.sh"),
				WithCustomArguments("tests/xml/scan_error_other.xml"),
			},

			expectedResult: &Run{
				Scanner: "fake_nmap",
				Args:    "nmap test",
			},
			wantErr: require.Error,
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			ctx := t.Context()
			if test.testTimeout {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 99*time.Hour)

				go (func() {
					// Cancel context to force timeout
					defer cancel()
					time.Sleep(1 * time.Millisecond)
				})()
			}

			options := append([]Option{}, test.options...)
			if test.useContainer {
				containerOptions := nmapContainerOptions(t)
				options = append(containerOptions, options...)
			}

			s, err := NewScanner(options...)
			require.NoError(t, err)

			result, err := s.Run(ctx)
			test.wantErr(t, err)

			compareResults(t, test.expectedResult, result)
		})
	}
}
