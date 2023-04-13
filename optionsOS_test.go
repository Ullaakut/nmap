package nmap

import (
	"context"
	"reflect"
	"testing"
)

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
