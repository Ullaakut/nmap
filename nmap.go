// Package nmap provides idiomatic `nmap` bindings for go developers.
package nmap

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"

	"github.com/pkg/errors"
)

// Scanner represents an Nmap scanner.
type Scanner struct {
	args       []string
	binaryPath string
	ctx        context.Context
}

// Run runs nmap synchronously and returns the result of the scan.
func (s *Scanner) Run() (*Run, error) {
	var stdout, stderr bytes.Buffer

	// Enable XML output
	s.args = append(s.args, "-oX")

	// Get XML output in stdout instead of writing it in a file
	s.args = append(s.args, "-")

	cmd := exec.Command(s.binaryPath, s.args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Start()
	if err != nil {
		return nil, err
	}

	// Make a goroutine to notify the select when the scan is done.
	done := make(chan error)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case <-s.ctx.Done():
		// Context was done before the scan was finished. The process is killed and a timeout
		// error is returned.
		cmd.Process.Kill()
		return nil, ErrTimeout
	case err := <-done:
		// Scan finished before timeout.
		if err != nil {
			return nil, err
		}

		if stderr.Len() > 0 {
			return nil, errors.New(stderr.String())
		}

		return Parse(stdout.Bytes())
	}
}

func (s Scanner) String() string {
	return fmt.Sprint(s.binaryPath, s.args)
}

// New creates a new Scanner, and can take options to apply to the scanner.
func New(options ...func(*Scanner)) (*Scanner, error) {
	scanner := &Scanner{}

	for _, option := range options {
		option(scanner)
	}

	if scanner.binaryPath == "" {
		var err error
		scanner.binaryPath, err = exec.LookPath("nmap")
		if err != nil {
			return nil, ErrNmapNotInstalled
		}
	}

	return scanner, nil
}

// WithContext adds a context to a scanner, to make it cancellable and able to timeout.
func WithContext(ctx context.Context) func(*Scanner) {
	return func(s *Scanner) {
		s.ctx = ctx
	}
}

// WithBinaryPath sets the nmap binary path for a scanner.
func WithBinaryPath(binaryPath string) func(*Scanner) {
	return func(s *Scanner) {
		s.binaryPath = binaryPath
	}
}

/*** Target specification ***/

// WithTarget sets the target of a scanner.
func WithTarget(target string) func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, target)
	}
}

// WithTargetExclusion sets the excluded targets of a scanner.
func WithTargetExclusion(target string) func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "--exclude")
		s.args = append(s.args, target)
	}
}

// WithTargetInput sets the input file name to set the targets.
func WithTargetInput(inputFileName string) func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "-iL")
		s.args = append(s.args, inputFileName)
	}
}

// WithTargetExclusionInput sets the input file name to set the target exclusions.
func WithTargetExclusionInput(inputFileName string) func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "--excludefile")
		s.args = append(s.args, inputFileName)
	}
}

// WithRandomTargets sets the amount of targets to randomly choose from the targets.
func WithRandomTargets(randomTargets int) func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "-iR")
		s.args = append(s.args, fmt.Sprint(randomTargets))
	}
}

/*** Host discovery ***/

// WithListScan sets the scan mode to simply list the targets to scan and not scan them.
func WithListScan() func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "-sL")
	}
}

// WithPingScan sets the scan mode to simply ping the targets to scan and not scan them.
func WithPingScan() func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "-sn")
	}
}

// WithSkipHostDiscovery sets the scan mode to skip the host discovery and consider all hosts
// as online.
func WithSkipHostDiscovery() func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "-Pn")
	}
}

/*** Port specification and scan order ***/

// WithPorts sets the ports which the scanner should scan on each host.
func WithPorts(ports string) func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "-p")
		s.args = append(s.args, ports)
	}
}

// WithPortExclusions sets the ports that the scanner should not scan on each host.
func WithPortExclusions(ports string) func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "--exclude-ports")
		s.args = append(s.args, ports)
	}
}
