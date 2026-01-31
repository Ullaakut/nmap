package nmap

import (
	"fmt"
	"strconv"
	"strings"
)

// WithPorts sets the ports which the scanner should scan on each host.
func WithPorts(ports ...string) Option {
	portList := strings.Join(ports, ",")

	return func(s *Scanner) error {
		// Find if any port is set.
		place := -1
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
			return nil
		}

		s.args = append(s.args, "-p", portList)

		return nil
	}
}

// WithPortExclusions sets the ports that the scanner should not scan on each host.
func WithPortExclusions(ports ...string) Option {
	portList := strings.Join(ports, ",")

	return func(s *Scanner) error {
		s.args = append(s.args, "--exclude-ports", portList)
		return nil
	}
}

// WithFastMode makes the scan faster by scanning fewer ports than the default scan.
func WithFastMode() Option {
	return func(s *Scanner) error {
		s.args = append(s.args, "-F")
		return nil
	}
}

// WithConsecutivePortScanning makes the scan go through ports consecutively instead of
// picking them out randomly.
func WithConsecutivePortScanning() Option {
	return func(s *Scanner) error {
		s.args = append(s.args, "-r")
		return nil
	}
}

// WithMostCommonPorts sets the scanner to go through the provided number of most
// common ports.
func WithMostCommonPorts(number int) Option {
	return func(s *Scanner) error {
		s.args = append(s.args, "--top-ports", strconv.Itoa(number))
		return nil
	}
}

// WithPortRatio sets the scanner to go the ports more common than the given ratio.
// Ratio must be a float between 0 and 1.
func WithPortRatio(ratio float32) Option {
	return func(s *Scanner) error {
		if ratio < 0 || ratio > 1 {
			return fmt.Errorf("value given to nmap.WithPortRatio() should be between 0 and 1: got %f", ratio)
		}

		s.args = append(s.args, "--port-ratio", fmt.Sprintf("%.1f", ratio))
		return nil
	}
}
