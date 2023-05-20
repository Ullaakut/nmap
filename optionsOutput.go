package nmap

import "fmt"

// WithVerbosity sets and increases the verbosity level of nmap.
func WithVerbosity(level int) Option {

	return func(s *Scanner) {
		if level < 0 || level > 10 {
			panic("value given to nmap.WithVerbosity() should be between 0 and 10")
		}
		s.args = append(s.args, fmt.Sprintf("-v%d", level))
	}
}

// WithDebugging sets and increases the debugging level of nmap.
func WithDebugging(level int) Option {
	return func(s *Scanner) {
		if level < 0 || level > 10 {
			panic("value given to nmap.WithDebugging() should be between 0 and 10")
		}
		s.args = append(s.args, fmt.Sprintf("-d%d", level))
	}
}

// WithReason makes nmap specify why a port is in a particular state.
func WithReason() Option {
	return func(s *Scanner) {
		s.args = append(s.args, "--reason")
	}
}

// WithOpenOnly makes nmap only show open ports.
func WithOpenOnly() Option {
	return func(s *Scanner) {
		s.args = append(s.args, "--open")
	}
}

// WithPacketTrace makes nmap show all packets sent and received.
func WithPacketTrace() Option {
	return func(s *Scanner) {
		s.args = append(s.args, "--packet-trace")
	}
}

// WithAppendOutput makes nmap append to files instead of overwriting them.
// Currently does nothing, since this library doesn't write in files.
func WithAppendOutput() Option {
	return func(s *Scanner) {
		s.args = append(s.args, "--append-output")
	}
}

// WithResumePreviousScan makes nmap continue a scan that was aborted,
// from an output file.
func WithResumePreviousScan(filePath string) Option {
	return func(s *Scanner) {
		s.args = append(s.args, "--resume")
		s.args = append(s.args, filePath)
	}
}

// WithStylesheet makes nmap apply an XSL stylesheet to transform its
// XML output to HTML.
func WithStylesheet(stylesheetPath string) Option {
	return func(s *Scanner) {
		s.args = append(s.args, "--stylesheet")
		s.args = append(s.args, stylesheetPath)
	}
}

// WithWebXML makes nmap apply the default nmap.org stylesheet to transform
// XML output to HTML. The stylesheet can be found at
// https://nmap.org/svn/docs/nmap.xsl
func WithWebXML() Option {
	return func(s *Scanner) {
		s.args = append(s.args, "--webxml")
	}
}

// WithNoStylesheet prevents the use of XSL stylesheets with the XML output.
func WithNoStylesheet() Option {
	return func(s *Scanner) {
		s.args = append(s.args, "--no-stylesheet")
	}
}

// WithNonInteractive disable runtime interactions via keyboard
func WithNonInteractive() Option {
	return func(s *Scanner) {
		s.args = append(s.Args(), "--noninteractive")
	}
}
