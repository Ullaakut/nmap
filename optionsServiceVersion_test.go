package nmap

import (
	"context"
	"reflect"
	"testing"
)

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
