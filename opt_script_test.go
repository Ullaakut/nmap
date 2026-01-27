package nmap

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestScriptScan(t *testing.T) {
	baseOptions := nmapContainerOptions(t)

	tests := []struct {
		description string

		targets []string
		options []Option

		expectedArgs []string
		wantErr      require.ErrorAssertionFunc
	}{
		{
			description: "default script scan",

			options: []Option{
				WithDefaultScript(),
			},

			expectedArgs: []string{
				"-sC",
			},
			wantErr: require.NoError,
		},
		{
			description: "custom script list",

			options: []Option{
				WithScripts("./scripts/", "/etc/nmap/nse/scripts"),
			},

			expectedArgs: []string{
				"--script=./scripts/,/etc/nmap/nse/scripts",
			},
			wantErr: require.NoError,
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

			expectedArgs: []string{
				`--script-args=pass=",{}=bar",user=foo,vulns.showall,whois={whodb=nofollow+ripe},xmpp-info.server_name=localhost`,
			},
			wantErr: require.NoError,
		},
		{
			description: "script arguments file",

			options: []Option{
				WithScriptArgumentsFile("/script_args.txt"),
			},

			expectedArgs: []string{
				"--script-args-file=/script_args.txt",
			},
			wantErr: require.NoError,
		},
		{
			description: "enable script trace",

			options: []Option{
				WithScriptTrace(),
			},

			expectedArgs: []string{
				"--script-trace",
			},
			wantErr: require.NoError,
		},
		{
			description: "update script database",

			options: []Option{
				WithScriptUpdateDB(),
			},

			expectedArgs: []string{
				"--script-updatedb",
			},
			wantErr: require.NoError,
		},
		{
			description: "set script timeout",

			options: []Option{
				WithScriptTimeout(40 * time.Second),
			},

			expectedArgs: []string{
				"--script-timeout",
				"40s",
			},
			wantErr: require.NoError,
		},
		{
			description: "set invalid script timeout",

			options: []Option{
				WithScriptTimeout(-40 * time.Second),
			},

			wantErr: require.Error,
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			options := append([]Option{}, baseOptions...)
			options = append(options, test.options...)

			s, err := NewScanner(options...)
			test.wantErr(t, err)
			if err != nil {
				return
			}

			assertArgsSuffix(t, s.args, test.expectedArgs)
		})
	}
}
