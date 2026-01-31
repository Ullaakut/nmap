package nmap

import (
	"errors"
	"fmt"
	"strconv"
)

// WithVerbosity sets and increases the verbosity level of nmap.
func WithVerbosity(level int) Option {
	return func(s *Scanner) error {
		if level < 0 || level > 10 {
			return fmt.Errorf("value given to nmap.WithVerbosity() should be between 0 and 10: got %d", level)
		}

		s.args = append(s.args, "-v"+strconv.Itoa(level))
		return nil
	}
}

// WithDebugging sets and increases the debugging level of nmap.
func WithDebugging(level int) Option {
	return func(s *Scanner) error {
		if level < 0 || level > 10 {
			return fmt.Errorf("value given to nmap.WithDebugging() should be between 0 and 10: got %d", level)
		}

		s.args = append(s.args, "-d"+strconv.Itoa(level))
		return nil
	}
}

// WithReason makes nmap specify why a port is in a particular state.
func WithReason() Option {
	return func(s *Scanner) error {
		s.args = append(s.args, "--reason")
		return nil
	}
}

// WithOpenOnly makes nmap only show open ports.
func WithOpenOnly() Option {
	return func(s *Scanner) error {
		s.args = append(s.args, "--open")
		return nil
	}
}

// WithPacketTrace makes nmap show all packets sent and received.
func WithPacketTrace() Option {
	return func(s *Scanner) error {
		s.args = append(s.args, "--packet-trace")
		return nil
	}
}

// WithAppendOutput makes nmap append to files instead of overwriting them.
// Currently does nothing, since this library doesn't write in files.
func WithAppendOutput() Option {
	return func(s *Scanner) error {
		s.args = append(s.args, "--append-output")
		return nil
	}
}

// WithResumePreviousScan makes nmap continue a scan that was aborted,
// from an output file.
func WithResumePreviousScan(filePath string) Option {
	return func(s *Scanner) error {
		s.args = append(s.args, "--resume", filePath)
		return nil
	}
}

// WithStylesheet makes nmap apply an XSL stylesheet to transform its
// XML output to HTML.
func WithStylesheet(stylesheetPath string) Option {
	return func(s *Scanner) error {
		s.args = append(s.args, "--stylesheet", stylesheetPath)
		return nil
	}
}

// WithWebXML makes nmap apply the default nmap.org stylesheet to transform
// XML output to HTML. The stylesheet can be found at
// https://nmap.org/svn/docs/nmap.xsl
func WithWebXML() Option {
	return func(s *Scanner) error {
		s.args = append(s.args, "--webxml")
		return nil
	}
}

// WithNoStylesheet prevents the use of XSL stylesheets with the XML output.
func WithNoStylesheet() Option {
	return func(s *Scanner) error {
		s.args = append(s.args, "--no-stylesheet")
		return nil
	}
}

// WithNonInteractive disable runtime interactions via keyboard.
func WithNonInteractive() Option {
	return func(s *Scanner) error {
		if s.progressHandler != nil {
			return errors.New("non-interactive mode cannot be used with progress updates")
		}

		s.interactive = false
		s.args = append(s.args, "--noninteractive")
		return nil
	}
}
