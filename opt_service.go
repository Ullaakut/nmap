package nmap

import (
	"fmt"
	"strconv"
)

// WithServiceInfo enables the probing of open ports to determine service and version
// info.
func WithServiceInfo() Option {
	return func(s *Scanner) error {
		s.args = append(s.args, "-sV")
		return nil
	}
}

// WithVersionDetectionOnAllPorts enables version detection on all specified ports,
// including port 9100 which is excluded by default.
// In other words, version detection is performed on all ports regardles of any Exclude directive.
func WithVersionDetectionOnAllPorts() Option {
	return func(s *Scanner) error {
		s.args = append(s.args, "--allports")
		return nil
	}
}

// WithVersionIntensity sets the level of intensity with which nmap should
// probe the open ports to get version information.
// Intensity should be a value between 0 (light) and 9 (try all probes). The
// default value is 7.
func WithVersionIntensity(intensity int16) Option {
	return func(s *Scanner) error {
		if intensity < 0 || intensity > 9 {
			return fmt.Errorf("value given to nmap.WithVersionIntensity() should be between 0 and 9, got %d", intensity)
		}

		s.args = append(s.args, "--version-intensity", strconv.Itoa(int(intensity)))
		return nil
	}
}

// WithVersionLight sets the level of intensity with which nmap should probe the
// open ports to get version information to 2. This makes version scanning much
// faster, but slightly less likely to identify services.
func WithVersionLight() Option {
	return func(s *Scanner) error {
		s.args = append(s.args, "--version-light")
		return nil
	}
}

// WithVersionAll sets the level of intensity with which nmap should probe the
// open ports to get version information to 9. This ensures that every single
// probe is attempted against each port.
func WithVersionAll() Option {
	return func(s *Scanner) error {
		s.args = append(s.args, "--version-all")
		return nil
	}
}

// WithVersionTrace causes Nmap to print out extensive debugging info about what
// version scanning is doing.
// TODO: See how this works along with XML output.
func WithVersionTrace() Option {
	return func(s *Scanner) error {
		s.args = append(s.args, "--version-trace")
		return nil
	}
}
