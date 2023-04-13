package nmap

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"
)

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
		{
			description: "set script timeout",

			options: []Option{
				WithScriptTimeout(40 * time.Second),
			},

			expectedArgs: []string{
				"--script-timeout",
				"40000ms",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			s, err := NewScanner(context.TODO(), test.options...)
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
