package nmap

// WithOSDetection enables OS detection.
func WithOSDetection() Option {
	return func(s *Scanner) {
		s.args = append(s.args, "-O")
	}
}

// WithOSScanLimit sets the scanner to not even try OS detection against
// hosts that do have at least one open TCP port, as it is unlikely to be effective.
// This can save substantial time, particularly on -Pn scans against many hosts.
// It only matters when OS detection is requested with -O or -A.
func WithOSScanLimit() Option {
	return func(s *Scanner) {
		s.args = append(s.args, "--osscan-limit")
	}
}

// WithOSScanGuess makes nmap attempt to guess the OS more aggressively.
func WithOSScanGuess() Option {
	return func(s *Scanner) {
		s.args = append(s.args, "--osscan-guess")
	}
}
