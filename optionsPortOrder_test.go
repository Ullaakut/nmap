package nmap

import (
	"context"
	"reflect"
	"testing"
)

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
