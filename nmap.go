// Package nmap provides idiomatic `nmap` bindings for go developers.
package nmap

import (
	"bufio"
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"
)

// ScanRunner represents something that can run a scan.
type ScanRunner interface {
	Run() (result *Run, warnings []string, err error)
}

// Streamer constantly streams the stdout.
type Streamer interface {
	Write(d []byte) (int, error)
	Bytes() []byte
}

// Scanner represents an Nmap scanner.
type Scanner struct {
	cmd               *exec.Cmd
	modifySysProcAttr func(*syscall.SysProcAttr)

	args       []string
	binaryPath string
	ctx        context.Context

	portFilter func(Port) bool
	hostFilter func(Host) bool

	stderr, stdout bufio.Scanner
}

// ArgOption is a function that is used for grouping of Scanner options.
// ArgOption adds or removes nmap command line arguments.
type ArgOption func(*Scanner)

// NewScanner creates a new Scanner, and can take options to apply to the scanner.
func NewScanner(options ...ArgOption) (*Scanner, error) {
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

	if scanner.ctx == nil {
		scanner.ctx = context.Background()
	}

	return scanner, nil
}

// Run runs nmap synchronously and returns the result of the scan.
func (s *Scanner) Run() (result *Run, warnings []string, err error) {
	var (
		stdout, stderr bytes.Buffer
		resume         bool
	)

	args := s.args

	for _, arg := range args {
		if arg == "--resume" {
			resume = true
			break
		}
	}

	if !resume {
		// Enable XML output
		args = append(args, "-oX")

		// Get XML output in stdout instead of writing it in a file
		args = append(args, "-")
	}

	// Prepare nmap process
	cmd := exec.Command(s.binaryPath, args...)
	if s.modifySysProcAttr != nil {
		s.modifySysProcAttr(cmd.SysProcAttr)
	}
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Run nmap process
	err = cmd.Start()
	if err != nil {
		return nil, warnings, err
	}

	// Make a goroutine to notify the select when the scan is done.
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	// Wait for nmap process or timeout
	select {
	case <-s.ctx.Done():

		// Context was done before the scan was finished.
		// The process is killed and a timeout error is returned.
		_ = cmd.Process.Kill()

		return nil, warnings, ErrScanTimeout
	case <-done:

		// Process nmap stderr output containing none-critical errors and warnings
		// Everyone needs to check whether one or some of these warnings is a hard issue in their use case
		if stderr.Len() > 0 {
			warnings = strings.Split(strings.Trim(stderr.String(), "\n"), "\n")
		}

		// Check for warnings that will inevitably lead to parsing errors, hence, have priority.
		if err := analyzeWarnings(warnings); err != nil {
			return nil, warnings, err
		}

		// Parse nmap xml output. Usually nmap always returns valid XML, even if there is a scan error.
		// Potentially available warnings are returned too, but probably not the reason for a broken XML.
		result, err := Parse(stdout.Bytes())
		if err != nil {
			warnings = append(warnings, err.Error()) // Append parsing error to warnings for those who are interested.
			return nil, warnings, ErrParseOutput
		}

		// Critical scan errors are reflected in the XML.
		if result != nil && len(result.Stats.Finished.ErrorMsg) > 0 {
			switch {
			case strings.Contains(result.Stats.Finished.ErrorMsg, "Error resolving name"):
				return result, warnings, ErrResolveName
			// TODO: Add cases for other known errors we might want to guard.
			default:
				return result, warnings, fmt.Errorf(result.Stats.Finished.ErrorMsg)
			}
		}

		// Call filters if they are set.
		if s.portFilter != nil {
			result = choosePorts(result, s.portFilter)
		}
		if s.hostFilter != nil {
			result = chooseHosts(result, s.hostFilter)
		}

		// Return result, optional warnings but no error
		return result, warnings, nil
	}
}

// RunWithProgress runs nmap synchronously and returns the result of the scan.
// It needs a channel to constantly stream the progress.
func (s *Scanner) RunWithProgress(liveProgress chan<- float32) (result *Run, warnings []string, err error) {
	var stdout, stderr bytes.Buffer

	args := s.args

	// Enable XML output.
	args = append(args, "-oX")

	// Get XML output in stdout instead of writing it in a file.
	args = append(args, "-")

	// Enable progress output every second.
	args = append(args, "--stats-every", "1s")

	// Prepare nmap process.
	cmd := exec.Command(s.binaryPath, args...)
	if s.modifySysProcAttr != nil {
		s.modifySysProcAttr(cmd.SysProcAttr)
	}
	cmd.Stderr = &stderr
	cmd.Stdout = &stdout

	// Run nmap process.
	err = cmd.Start()
	if err != nil {
		return nil, warnings, err
	}

	// Make a goroutine to notify the select when the scan is done.
	done := make(chan error, 1)
	doneProgress := make(chan bool, 1)
	go func() {
		done <- cmd.Wait()
	}()

	// Make goroutine to check the progress every second.
	// Listening for channel doneProgress.
	go func() {
		type progress struct {
			TaskProgress []TaskProgress `xml:"taskprogress" json:"task_progress"`
		}
		p := &progress{}
		for {
			select {
			case <-doneProgress:
				close(liveProgress)
				return
			default:
				time.Sleep(time.Second)
				_ = xml.Unmarshal(stdout.Bytes(), p)
				//result, _ := Parse(stdout.Bytes())
				if len(p.TaskProgress) > 0 {
					liveProgress <- p.TaskProgress[len(p.TaskProgress)-1].Percent
				}
			}
		}
	}()

	// Wait for nmap process or timeout.
	select {
	case <-s.ctx.Done():
		// Trigger progress function exit.
		close(doneProgress)

		// Context was done before the scan was finished.
		// The process is killed and a timeout error is returned.
		_ = cmd.Process.Kill()

		return nil, warnings, ErrScanTimeout
	case <-done:
		// Trigger progress function exit.
		close(doneProgress)

		// Process nmap stderr output containing none-critical errors and warnings.
		// Everyone needs to check whether one or some of these warnings is a hard issue in their use case.
		if stderr.Len() > 0 {
			warnings = strings.Split(strings.Trim(stderr.String(), "\n"), "\n")
		}

		// Check for warnings that will inevitably lead to parsing errors, hence, have priority.
		if err := analyzeWarnings(warnings); err != nil {
			return nil, warnings, err
		}

		// Parse nmap xml output. Usually nmap always returns valid XML, even if there is a scan error.
		// Potentially available warnings are returned too, but probably not the reason for a broken XML.
		result, err := Parse(stdout.Bytes())
		if err != nil {
			warnings = append(warnings, err.Error()) // Append parsing error to warnings for those who are interested.
			return nil, warnings, ErrParseOutput
		}

		// Critical scan errors are reflected in the XML.
		if result != nil && len(result.Stats.Finished.ErrorMsg) > 0 {
			switch {
			case strings.Contains(result.Stats.Finished.ErrorMsg, "Error resolving name"):
				return result, warnings, ErrResolveName
			// TODO: Add cases for other known errors we might want to guard.
			default:
				return result, warnings, fmt.Errorf(result.Stats.Finished.ErrorMsg)
			}
		}

		// Call filters if they are set.
		if s.portFilter != nil {
			result = choosePorts(result, s.portFilter)
		}
		if s.hostFilter != nil {
			result = chooseHosts(result, s.hostFilter)
		}

		// Return result, optional warnings but no error.
		return result, warnings, nil
	}
}

// RunWithStreamer runs nmap synchronously. The XML output is written directly to a file.
// It uses a streamer interface to constantly stream the stdout.
func (s *Scanner) RunWithStreamer(stream Streamer, file string) (warnings []string, err error) {

	args := s.args

	// Enable XML output.
	args = append(args, "-oX")

	// Get XML output in stdout instead of writing it in a file.
	args = append(args, file)

	// Enable progress output every second.
	args = append(args, "--stats-every", "5s")

	// Prepare nmap process.
	cmd := exec.CommandContext(s.ctx, s.binaryPath, args...)
	if s.modifySysProcAttr != nil {
		s.modifySysProcAttr(cmd.SysProcAttr)
	}

	// Write stderr to buffer.
	stderrBuf := bytes.Buffer{}
	cmd.Stderr = &stderrBuf

	// Connect to the StdoutPipe.
	stdoutIn, err := cmd.StdoutPipe()
	if err != nil {
		return warnings, errors.WithMessage(err, "connect to StdoutPipe failed")
	}
	stdout := stream

	// Run nmap process.
	if err := cmd.Start(); err != nil {
		return warnings, errors.WithMessage(err, "start command failed")
	}

	// Copy stdout to pipe.
	g, _ := errgroup.WithContext(s.ctx)
	g.Go(func() error {
		_, err = io.Copy(stdout, stdoutIn)
		return err
	})

	cmdErr := cmd.Wait()
	if err := g.Wait(); err != nil {
		warnings = append(warnings, errors.WithMessage(err, "read from stdout failed").Error())
	}
	if cmdErr != nil {
		return warnings, errors.WithMessage(err, "nmap command failed")
	}
	// Process nmap stderr output containing none-critical errors and warnings.
	// Everyone needs to check whether one or some of these warnings is a hard issue in their use case.
	if stderrBuf.Len() > 0 {
		warnings = append(warnings, strings.Split(strings.Trim(stderrBuf.String(), "\n"), "\n")...)
	}

	// Check for warnings that will inevitably lead to parsing errors, hence, have priority.
	if err := analyzeWarnings(warnings); err != nil {
		return warnings, err
	}

	// Return result, optional warnings but no error.
	return warnings, nil
}

// RunAsync runs nmap asynchronously and returns error.
// TODO: RunAsync should return warnings as well.
func (s *Scanner) RunAsync() error {

	args := s.args

	// Enable XML output.
	args = append(args, "-oX")

	// Get XML output in stdout instead of writing it in a file.
	args = append(args, "-")
	s.cmd = exec.Command(s.binaryPath, args...)

	if s.modifySysProcAttr != nil {
		s.modifySysProcAttr(s.cmd.SysProcAttr)
	}

	stderr, err := s.cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("unable to get error output from asynchronous nmap run: %v", err)
	}

	stdout, err := s.cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("unable to get standard output from asynchronous nmap run: %v", err)
	}

	s.stdout = *bufio.NewScanner(stdout)
	s.stderr = *bufio.NewScanner(stderr)

	if err := s.cmd.Start(); err != nil {
		return fmt.Errorf("unable to execute asynchronous nmap run: %v", err)
	}

	go func() {
		<-s.ctx.Done()
		_ = s.cmd.Process.Kill()
	}()

	return nil
}

// Wait waits for the cmd to finish and returns error.
func (s *Scanner) Wait() error {
	return s.cmd.Wait()
}

// GetStdout returns stdout variable for scanner.
func (s *Scanner) GetStdout() bufio.Scanner {
	return s.stdout
}

// GetStderr returns stderr variable for scanner.
func (s *Scanner) GetStderr() bufio.Scanner {
	return s.stderr
}

// AddOptions sets more scan options after the scan is created.
func (s *Scanner) AddOptions(options ...ArgOption) {
	for _, option := range options {
		option(s)
	}
}

// Args return the list of nmap args
func (s *Scanner) Args() []string {
	return s.args
}

func chooseHosts(result *Run, filter func(Host) bool) *Run {
	var filteredHosts []Host

	for _, host := range result.Hosts {
		if filter(host) {
			filteredHosts = append(filteredHosts, host)
		}
	}

	result.Hosts = filteredHosts

	return result
}

func choosePorts(result *Run, filter func(Port) bool) *Run {
	for idx := range result.Hosts {
		var filteredPorts []Port

		for _, port := range result.Hosts[idx].Ports {
			if filter(port) {
				filteredPorts = append(filteredPorts, port)
			}
		}

		result.Hosts[idx].Ports = filteredPorts
	}

	return result
}

func analyzeWarnings(warnings []string) error {
	// Check for warnings that will inevitably lead to parsing errors, hence, have priority.
	for _, warning := range warnings {
		switch {
		case strings.Contains(warning, "Malloc Failed!"):
			return ErrMallocFailed
		// TODO: Add cases for other known errors we might want to guard.
		default:
		}
	}
	return nil
}

// WithContext adds a context to a scanner, to make it cancellable and able to timeout.
func WithContext(ctx context.Context) ArgOption {
	return func(s *Scanner) {
		s.ctx = ctx
	}
}

// WithBinaryPath sets the nmap binary path for a scanner.
func WithBinaryPath(binaryPath string) ArgOption {
	return func(s *Scanner) {
		s.binaryPath = binaryPath
	}
}

// WithCustomArguments sets custom arguments to give to the nmap binary.
// There should be no reason to use this, unless you are using a custom build
// of nmap or that this repository isn't up to date with the latest options
// of the official nmap release.
// You can use this as a quick way to paste an nmap command into your go code,
// but remember that the whole purpose of this repository is to be idiomatic,
// provide type checking, enums for the values that can be passed, etc.
func WithCustomArguments(args ...string) ArgOption {
	return func(s *Scanner) {
		s.args = append(s.args, args...)
	}
}

// WithFilterPort allows to set a custom function to filter out ports that
// don't fulfill a given condition. When the given function returns true,
// the port is kept, otherwise it is removed from the result. Can be used
// along with WithFilterHost.
func WithFilterPort(portFilter func(Port) bool) ArgOption {
	return func(s *Scanner) {
		s.portFilter = portFilter
	}
}

// WithFilterHost allows to set a custom function to filter out hosts that
// don't fulfill a given condition. When the given function returns true,
// the host is kept, otherwise it is removed from the result. Can be used
// along with WithFilterPort.
func WithFilterHost(hostFilter func(Host) bool) ArgOption {
	return func(s *Scanner) {
		s.hostFilter = hostFilter
	}
}
