package nmap

import (
	"fmt"
	"slices"
	"strings"
	"time"
)

// WithDefaultScript sets the scanner to perform a script scan using the default
// set of scripts. It is equivalent to --script=default. Some of the scripts in
// this category are considered intrusive and should not be run against a target
// network without permission.
func WithDefaultScript() Option {
	return func(s *Scanner) error {
		s.args = append(s.args, "-sC")
		return nil
	}
}

// WithScripts sets the scanner to perform a script scan using the enumerated
// scripts, script directories and script categories.
func WithScripts(scripts ...string) Option {
	scriptList := strings.Join(scripts, ",")

	return func(s *Scanner) error {
		s.args = append(s.args, "--script="+scriptList)
		return nil
	}
}

// WithScriptArguments provides arguments for scripts.
// If a value is the empty string, the key is used as a flag.
func WithScriptArguments(arguments map[string]string) Option {
	// Properly format the argument list from the map.
	// Complex example:
	// user=foo,pass=",{}=bar",whois={whodb=nofollow+ripe},xmpp-info.server_name=localhost,vulns.showall
	scriptArgs := make([]string, 0, len(arguments))
	for key, value := range arguments {
		str := key
		if value != "" {
			str = fmt.Sprintf("%s=%s", key, value)
		}

		scriptArgs = append(scriptArgs, str)
	}

	// Ensure consistent ordering.
	slices.Sort(scriptArgs)
	args := strings.Join(scriptArgs, ",")

	return func(s *Scanner) error {
		s.args = append(s.args, "--script-args="+args)
		return nil
	}
}

// WithScriptArgumentsFile provides arguments for scripts from a file.
func WithScriptArgumentsFile(inputFilePath string) Option {
	return func(s *Scanner) error {
		s.args = append(s.args, "--script-args-file="+inputFilePath)
		return nil
	}
}

// WithScriptTrace makes the scripts show all data sent and received.
func WithScriptTrace() Option {
	return func(s *Scanner) error {
		s.args = append(s.args, "--script-trace")
		return nil
	}
}

// WithScriptUpdateDB updates the script database.
func WithScriptUpdateDB() Option {
	return func(s *Scanner) error {
		s.args = append(s.args, "--script-updatedb")
		return nil
	}
}

// WithScriptTimeout sets the script timeout.
func WithScriptTimeout(timeout time.Duration) Option {
	return func(s *Scanner) error {
		formatted, err := formatNmapDuration(timeout)
		if err != nil {
			return fmt.Errorf("format script timeout: %w", err)
		}

		s.args = append(s.args, "--script-timeout")
		s.args = append(s.args, formatted)
		return nil
	}
}
