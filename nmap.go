// Package nmap provides idiomatic `nmap` bindings for go developers.
package nmap

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"github.com/mattn/go-isatty"
)

// ScanRunner represents something that can run a scan.
type ScanRunner interface {
	Run(ctx context.Context) (*Run, error)
}

// AsyncScanRunner represents something that can run a scan asynchronously.
type AsyncScanRunner interface {
	RunAsync(ctx context.Context) (<-chan []byte, <-chan []byte, <-chan RunResult, error)
}

// Scanner represents n Nmap scanner.
type Scanner struct {
	modifySysProcAttr func(*syscall.SysProcAttr)

	args       []string
	binaryPath string

	portFilter func(Port) bool
	hostFilter func(Host) bool

	progressHandler func(TaskProgress)

	interactive bool
	toFile      *string
}

// RunResult represents the result of an asynchronous run.
type RunResult struct {
	Result *Run
	Err    error
}

// Option is a function that is used for grouping of Scanner options.
// Option adds or removes nmap command line arguments.
type Option func(*Scanner) error

// NewScanner creates a new Scanner, and can take options to apply to the scanner.
func NewScanner(options ...Option) (*Scanner, error) {
	scanner := Scanner{
		interactive: isatty.IsTerminal(os.Stdin.Fd()),
	}

	for _, option := range options {
		err := option(&scanner)
		if err != nil {
			return nil, fmt.Errorf("applying option: %w", err)
		}
	}

	if scanner.binaryPath == "" {
		var err error
		scanner.binaryPath, err = exec.LookPath("nmap")
		if err != nil {
			return nil, ErrNmapNotInstalled
		}
	}

	return &scanner, nil
}

// ToFile enables the Scanner to write the nmap XML output to a given path.
// Nmap writes the normal CLI output to stdout.
// The XML is parsed from file after the scan is finished.
func (s *Scanner) ToFile(file string) (*Scanner, error) {
	if s.progressHandler != nil {
		return nil, errors.New("progress updates require XML on stdout; do not use WithProgress with ToFile")
	}

	s.toFile = &file
	return s, nil
}

// Run executes nmap with the enabled options and parses the resulting output.
func (s *Scanner) Run(ctx context.Context) (*Run, error) {
	cmd := s.newCmd(ctx)

	if s.progressHandler != nil {
		return s.runAndParseWithProgress(ctx, cmd)
	}

	return s.runAndParse(ctx, cmd)
}

// RunAsync executes nmap in a goroutine and streams stdout and stderr
// through channels. It also returns a channel that receives the final
// result and error when the scan completes.
func (s *Scanner) RunAsync(ctx context.Context) (<-chan []byte, <-chan []byte, <-chan RunResult, error) {
	return s.runAsync(ctx)
}

// AddOptions sets more scan options after the scan is created.
func (s *Scanner) AddOptions(options ...Option) (*Scanner, error) {
	for _, option := range options {
		err := option(s)
		if err != nil {
			return s, fmt.Errorf("applying option: %w", err)
		}
	}
	return s, nil
}

// Args return the list of nmap args.
func (s *Scanner) Args() []string {
	return s.args
}

func chooseHosts(result *Run, filter func(Host) bool) {
	var filteredHosts []Host

	for _, host := range result.Hosts {
		if filter(host) {
			filteredHosts = append(filteredHosts, host)
		}
	}

	result.Hosts = filteredHosts
}

func choosePorts(result *Run, filter func(Port) bool) {
	for idx := range result.Hosts {
		var filteredPorts []Port

		for _, port := range result.Hosts[idx].Ports {
			if filter(port) {
				filteredPorts = append(filteredPorts, port)
			}
		}

		result.Hosts[idx].Ports = filteredPorts
	}
}

// WithCustomArguments sets custom arguments to give to the nmap binary.
// There should be no reason to use this, unless you are using a custom build
// of nmap or that this repository isn't up to date with the latest options
// of the official nmap release.
//
// Deprecated: You can use this as a quick way to paste an nmap command into your go code,
// but remember that the whole purpose of this repository is to be idiomatic,
// provide type checking, enums for the values that can be passed, etc.
func WithCustomArguments(args ...string) Option {
	return func(s *Scanner) error {
		s.args = append(s.args, args...)
		return nil
	}
}

// WithBinaryPath sets the nmap binary path for a scanner.
func WithBinaryPath(binaryPath string) Option {
	return func(s *Scanner) error {
		s.binaryPath = binaryPath
		return nil
	}
}

// WithFilterPort allows to set a custom function to filter out ports that
// don't fulfill a given condition. When the given function returns true,
// the port is kept, otherwise it is removed from the result. Can be used
// along with WithFilterHost.
func WithFilterPort(portFilter func(Port) bool) Option {
	return func(s *Scanner) error {
		s.portFilter = portFilter
		return nil
	}
}

// WithFilterHost allows to set a custom function to filter out hosts that
// don't fulfill a given condition. When the given function returns true,
// the host is kept, otherwise it is removed from the result. Can be used
// along with WithFilterPort.
func WithFilterHost(hostFilter func(Host) bool) Option {
	return func(s *Scanner) error {
		s.hostFilter = hostFilter
		return nil
	}
}
