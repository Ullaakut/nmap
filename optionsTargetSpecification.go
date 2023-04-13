package nmap

import (
	"fmt"
)

// WithTargets sets the target of a scanner.
func WithTargets(targets ...string) Option {
	return func(s *Scanner) {
		s.args = append(s.args, targets...)
	}
}

// WithTargetExclusion sets the excluded targets of a scanner.
func WithTargetExclusion(target string) Option {
	return func(s *Scanner) {
		s.args = append(s.args, "--exclude")
		s.args = append(s.args, target)
	}
}

// WithTargetInput sets the input file name to set the targets.
func WithTargetInput(inputFileName string) Option {
	return func(s *Scanner) {
		s.args = append(s.args, "-iL")
		s.args = append(s.args, inputFileName)
	}
}

// WithTargetExclusionInput sets the input file name to set the target exclusions.
func WithTargetExclusionInput(inputFileName string) Option {
	return func(s *Scanner) {
		s.args = append(s.args, "--excludefile")
		s.args = append(s.args, inputFileName)
	}
}

// WithRandomTargets sets the amount of targets to randomly choose from the targets.
func WithRandomTargets(randomTargets int) Option {
	return func(s *Scanner) {
		s.args = append(s.args, "-iR")
		s.args = append(s.args, fmt.Sprint(randomTargets))
	}
}

// WithUnique makes each address be scanned only once.
// The default behavior is to scan each address as many times
// as it is specified in the target list, such as when network
// ranges overlap or different hostnames resolve to the same
// address.
func WithUnique() Option {
	return func(s *Scanner) {
		s.args = append(s.args, "--unique")
	}
}
