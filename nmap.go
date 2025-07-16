// Package nmap provides idiomatic `nmap` bindings for go developers.
package nmap

import (
	"bufio"
	"context"
	"io"
	"os/exec"
	"strings"
	"syscall"
)

// ScanRunner represents something that can run a scan.
type ScanRunner interface {
	Run() (result *Run, warnings []string, err error)
}

// Scanner represents n Nmap scanner.
type Scanner struct {
	modifySysProcAttr func(*syscall.SysProcAttr)

	args       []string
	binaryPath string
	ctx        context.Context

	portFilter func(Port) bool
	hostFilter func(Host) bool

	doneAsync    chan error
	liveProgress chan float32
	streamer     io.Writer
	toFile       *string
}

// Option is a function that is used for grouping of Scanner options.
// Option adds or removes nmap command line arguments.
type Option func(*Scanner)

// NewScanner creates a new Scanner, and can take options to apply to the scanner.
func NewScanner(ctx context.Context, options ...Option) (*Scanner, error) {
	scanner := &Scanner{
		doneAsync:    nil,
		liveProgress: nil,
		streamer:     nil,
		ctx:          ctx,
	}

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

// Async will run the nmap scan asynchronously. You need to provide a channel with error type.
// When the scan is finished an error or nil will be piped through this channel.
func (s *Scanner) Async(doneAsync chan error) *Scanner {
	s.doneAsync = doneAsync
	return s
}

// Progress pipes the progress of nmap every 100ms. It needs a channel of type float.
func (s *Scanner) Progress(liveProgress chan float32) *Scanner {
	s.args = append(s.args, "--stats-every", "100ms")
	s.liveProgress = liveProgress
	return s
}

// ToFile enables the Scanner to write the nmap XML output to a given path.
// Nmap will write the normal CLI output to stdout. The XML is parsed from file after the scan is finished.
func (s *Scanner) ToFile(file string) *Scanner {
	s.toFile = &file
	return s
}

// Streamer takes an io.Writer that receives the XML output.
// So the stdout of nmap will be duplicated to the given stream and *Run.
// This will not disable parsing the output to the struct.
func (s *Scanner) Streamer(stream io.Writer) *Scanner {
	s.streamer = stream
	return s
}

// Run will run the Scanner with the enabled options.
// You need to create a Run struct and warnings array first so the function can parse it.
func (s *Scanner) Run() (result *Run, warnings *[]string, err error) {
	warnings = &[]string{} // Instantiate warnings array

	args := s.args

	// Write XML to standard output.
	// If toFile is set then write XML to file.
	if s.toFile != nil {
		args = append(args, "-oX", *s.toFile)
	} else {
		args = append(args, "-oX", "-")
	}

	// Prepare nmap process.
	cmd := exec.CommandContext(s.ctx, s.binaryPath, args...)
	if s.modifySysProcAttr != nil {
		s.modifySysProcAttr(cmd.SysProcAttr)
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return result, warnings, err
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return result, warnings, err
	}

	// According to cmd.StdoutPipe() doc, we must not "call Wait before all reads from the pipe have completed"

	result = &Run{}
	// Run nmap process.
	err = cmd.Start()
	s.processNmapResult(result, warnings, stdoutPipe, stderrPipe)
	cmd.Wait()
	if err != nil {
		return result, warnings, err
	}
	return result, warnings, err
}

// AddOptions sets more scan options after the scan is created.
func (s *Scanner) AddOptions(options ...Option) *Scanner {
	for _, option := range options {
		option(s)
	}
	return s
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

func (s *Scanner) processNmapResult(result *Run, warnings *[]string, stdout, stderr io.Reader) error {
	// Wait for nmap to finish.
	// Check for errors indicated by stderr output.
	if err := checkStdErr(stderr, warnings); err != nil {
		return err
	}
	return Parse(stdout, result)
}

// checkStdErr writes the output of stderr to the warnings array.
// It also processes nmap stderr output containing none-critical errors and warnings.
func checkStdErr(stderr io.Reader, warnings *[]string) error {

	// Check for warnings that will inevitably lead to parsing errors, hence, have priority.
	scanner := bufio.NewScanner(stderr)
	for scanner.Scan() {
		warning := scanner.Text()
		*warnings = append(*warnings, warning)
		switch {
		case strings.Contains(warning, "Malloc Failed!"):
			return ErrMallocFailed
		case strings.Contains(warning, "requires root privileges."):
			return ErrRequiresRoot
		// TODO: Add cases for other known errors we might want to guard.
		default:
		}
	}
	return nil
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
	return func(s *Scanner) {
		s.args = append(s.args, args...)
	}
}

// WithBinaryPath sets the nmap binary path for a scanner.
func WithBinaryPath(binaryPath string) Option {
	return func(s *Scanner) {
		s.binaryPath = binaryPath
	}
}

// WithFilterPort allows to set a custom function to filter out ports that
// don't fulfill a given condition. When the given function returns true,
// the port is kept, otherwise it is removed from the result. Can be used
// along with WithFilterHost.
func WithFilterPort(portFilter func(Port) bool) Option {
	return func(s *Scanner) {
		s.portFilter = portFilter
	}
}

// WithFilterHost allows to set a custom function to filter out hosts that
// don't fulfill a given condition. When the given function returns true,
// the host is kept, otherwise it is removed from the result. Can be used
// along with WithFilterPort.
func WithFilterHost(hostFilter func(Host) bool) Option {
	return func(s *Scanner) {
		s.hostFilter = hostFilter
	}
}
