package nmap

import (
	"strconv"
	"strings"
)

// WithTargets sets the target of a scanner.
func WithTargets(targets ...string) Option {
	return func(s *Scanner) error {
		s.args = append(s.args, targets...)
		return nil
	}
}

// WithTargetExclusions sets the excluded targets of a scanner.
func WithTargetExclusions(targets ...string) Option {
	targetList := strings.Join(targets, ",")

	return func(s *Scanner) error {
		s.args = append(s.args, "--exclude", targetList)
		return nil
	}
}

// WithTargetInput sets the input file name to set the targets.
func WithTargetInput(inputFileName string) Option {
	return func(s *Scanner) error {
		s.args = append(s.args, "-iL", inputFileName)
		return nil
	}
}

// WithTargetExclusionInput sets the input file name to set the target exclusions.
func WithTargetExclusionInput(inputFileName string) Option {
	return func(s *Scanner) error {
		s.args = append(s.args, "--excludefile", inputFileName)
		return nil
	}
}

// WithRandomTargets sets the amount of targets to randomly choose from the targets.
func WithRandomTargets(randomTargets int) Option {
	return func(s *Scanner) error {
		s.args = append(s.args, "-iR", strconv.Itoa(randomTargets))
		return nil
	}
}

// WithUnique makes each address be scanned only once.
// The default behavior is to scan each address as many times
// as it is specified in the target list, such as when network
// ranges overlap or different hostnames resolve to the same
// address.
func WithUnique() Option {
	return func(s *Scanner) error {
		s.args = append(s.args, "--unique")
		return nil
	}
}
