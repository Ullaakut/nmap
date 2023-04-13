package nmap

import (
	"fmt"
	"strings"
)

// WithPorts sets the ports which the scanner should scan on each host.
func WithPorts(ports ...string) Option {
	portList := strings.Join(ports, ",")

	return func(s *Scanner) {
		// Find if any port is set.
		var place = -1
		for p, value := range s.args {
			if value == "-p" {
				place = p
				break
			}
		}

		// Add ports.
		if place >= 0 {
			if len(s.args)-1 == place {
				s.args = append(s.args, "")
			} else {
				portList = s.args[place+1] + "," + portList
			}
			s.args[place+1] = portList
		} else {
			s.args = append(s.args, "-p")
			s.args = append(s.args, portList)
		}
	}
}

// WithPortExclusions sets the ports that the scanner should not scan on each host.
func WithPortExclusions(ports ...string) Option {
	portList := strings.Join(ports, ",")

	return func(s *Scanner) {
		s.args = append(s.args, "--exclude-ports")
		s.args = append(s.args, portList)
	}
}

// WithFastMode makes the scan faster by scanning fewer ports than the default scan.
func WithFastMode() Option {
	return func(s *Scanner) {
		s.args = append(s.args, "-F")
	}
}

// WithConsecutivePortScanning makes the scan go through ports consecutively instead of
// picking them out randomly.
func WithConsecutivePortScanning() Option {
	return func(s *Scanner) {
		s.args = append(s.args, "-r")
	}
}

// WithMostCommonPorts sets the scanner to go through the provided number of most
// common ports.
func WithMostCommonPorts(number int) Option {
	return func(s *Scanner) {
		s.args = append(s.args, "--top-ports")
		s.args = append(s.args, fmt.Sprint(number))
	}
}

// WithPortRatio sets the scanner to go the ports more common than the given ratio.
// Ratio must be a float between 0 and 1.
func WithPortRatio(ratio float32) Option {
	return func(s *Scanner) {
		if ratio < 0 || ratio > 1 {
			panic("value given to nmap.WithPortRatio() should be between 0 and 1")
		}

		s.args = append(s.args, "--port-ratio")
		s.args = append(s.args, fmt.Sprintf("%.1f", ratio))
	}
}
