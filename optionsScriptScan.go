package nmap

import (
	"fmt"
	"strings"
	"time"
)

// WithDefaultScript sets the scanner to perform a script scan using the default
// set of scripts. It is equivalent to --script=default. Some of the scripts in
// this category are considered intrusive and should not be run against a target
// network without permission.
func WithDefaultScript() Option {
	return func(s *Scanner) {
		s.args = append(s.args, "-sC")
	}
}

// WithScripts sets the scanner to perform a script scan using the enumerated
// scripts, script directories and script categories.
func WithScripts(scripts ...string) Option {
	scriptList := strings.Join(scripts, ",")

	return func(s *Scanner) {
		s.args = append(s.args, fmt.Sprintf("--script=%s", scriptList))
	}
}

// WithScriptArguments provides arguments for scripts. If a value is the empty string, the key will be used as a flag.
func WithScriptArguments(arguments map[string]string) Option {
	var argList string

	// Properly format the argument list from the map.
	// Complex example:
	// user=foo,pass=",{}=bar",whois={whodb=nofollow+ripe},xmpp-info.server_name=localhost,vulns.showall
	for key, value := range arguments {
		str := ""
		if value == "" {
			str = key
		} else {
			str = fmt.Sprintf("%s=%s", key, value)
		}

		argList = strings.Join([]string{argList, str}, ",")
	}

	argList = strings.TrimLeft(argList, ",")

	return func(s *Scanner) {
		s.args = append(s.args, fmt.Sprintf("--script-args=%s", argList))
	}
}

// WithScriptArgumentsFile provides arguments for scripts from a file.
func WithScriptArgumentsFile(inputFilePath string) Option {
	return func(s *Scanner) {
		s.args = append(s.args, fmt.Sprintf("--script-args-file=%s", inputFilePath))
	}
}

// WithScriptTrace makes the scripts show all data sent and received.
func WithScriptTrace() Option {
	return func(s *Scanner) {
		s.args = append(s.args, "--script-trace")
	}
}

// WithScriptUpdateDB updates the script database.
func WithScriptUpdateDB() Option {
	return func(s *Scanner) {
		s.args = append(s.args, "--script-updatedb")
	}
}

// WithScriptTimeout sets the script timeout.
func WithScriptTimeout(timeout time.Duration) Option {
	milliseconds := timeout.Round(time.Nanosecond).Nanoseconds() / 1000000

	return func(s *Scanner) {
		s.args = append(s.args, "--script-timeout")
		s.args = append(s.args, fmt.Sprintf("%dms", int(milliseconds)))
	}
}
