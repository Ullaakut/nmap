package nmap

import "fmt"

// WithServiceInfo enables the probing of open ports to determine service and version
// info.
func WithServiceInfo() Option {
	return func(s *Scanner) {
		s.args = append(s.args, "-sV")
	}
}

// WithVersionIntensity sets the level of intensity with which nmap should
// probe the open ports to get version information.
// Intensity should be a value between 0 (light) and 9 (try all probes). The
// default value is 7.
func WithVersionIntensity(intensity int16) Option {
	return func(s *Scanner) {
		if intensity < 0 || intensity > 9 {
			panic("value given to nmap.WithVersionIntensity() should be between 0 and 9")
		}

		s.args = append(s.args, "--version-intensity")
		s.args = append(s.args, fmt.Sprint(intensity))
	}
}

// WithVersionLight sets the level of intensity with which nmap should probe the
// open ports to get version information to 2. This will make version scanning much
// faster, but slightly less likely to identify services.
func WithVersionLight() Option {
	return func(s *Scanner) {
		s.args = append(s.args, "--version-light")
	}
}

// WithVersionAll sets the level of intensity with which nmap should probe the
// open ports to get version information to 9. This will ensure that every single
// probe is attempted against each port.
func WithVersionAll() Option {
	return func(s *Scanner) {
		s.args = append(s.args, "--version-all")
	}
}

// WithVersionTrace causes Nmap to print out extensive debugging info about what
// version scanning is doing.
// TODO: See how this works along with XML output.
func WithVersionTrace() Option {
	return func(s *Scanner) {
		s.args = append(s.args, "--version-trace")
	}
}
