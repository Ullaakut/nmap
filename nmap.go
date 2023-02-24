// Package nmap provides idiomatic `nmap` bindings for go developers.
package nmap

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
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

// ArgOption is a function that is used for grouping of Scanner options.
// ArgOption adds or removes nmap command line arguments.
type ArgOption func(*Scanner)

// NewScanner creates a new Scanner, and can take options to apply to the scanner.
func NewScanner(options ...ArgOption) (*Scanner, error) {
	scanner := &Scanner{
		doneAsync:    nil,
		liveProgress: nil,
		streamer:     nil,
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

	if scanner.ctx == nil {
		scanner.ctx = context.Background()
	}

	return scanner, nil
}

func (s *Scanner) Async(doneAsync chan error) *Scanner {
	s.doneAsync = doneAsync
	return s
}

func (s *Scanner) Progress(liveProgress chan float32) *Scanner {
	s.args = append(s.args, "--stats-every", "1s")
	s.liveProgress = liveProgress
	return s
}

func (s *Scanner) ToFile(file string) *Scanner {
	s.toFile = &file
	return s
}

func (s *Scanner) Streamer(stream io.Writer) *Scanner {
	s.streamer = stream
	return s
}

// Context adds a context to a scanner, to make it cancellable and able to timeout.
func (s *Scanner) Context(ctx context.Context) *Scanner {
	s.ctx = ctx
	return s
}

func (s *Scanner) Run(result *Run, warnings *[]string) (err error) {
	var stdoutPipe io.ReadCloser
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	args := s.args

	// Write XML to standard output.
	// If toFile is set then write XML to file and normal nmap output to stdout.
	if s.toFile != nil {
		args = append(args, "-oX", *s.toFile, "-oN", "-")
	} else {
		args = append(args, "-oX", "-")
	}

	// Prepare nmap process
	cmd := exec.CommandContext(s.ctx, s.binaryPath, args...)
	if s.modifySysProcAttr != nil {
		s.modifySysProcAttr(cmd.SysProcAttr)
	}
	stdoutPipe, err = cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stdoutDuplicate := io.TeeReader(stdoutPipe, &stdout)
	cmd.Stderr = &stderr

	var streamerGroup *errgroup.Group
	if s.streamer != nil {
		streamerGroup, _ = errgroup.WithContext(s.ctx)
		streamerGroup.Go(func() error {
			_, err = io.Copy(s.streamer, stdoutDuplicate)
			return err
		})
	} else {
		go io.Copy(ioutil.Discard, stdoutDuplicate)
	}

	// Run nmap process
	err = cmd.Start()
	if err != nil {
		return err
	}

	// Add goroutine that updates chan when command finished.
	done := make(chan error, 1)
	doneProgress := make(chan bool, 1)
	go func() {
		err := cmd.Wait()
		if streamerGroup != nil {
			streamerError := streamerGroup.Wait()
			if streamerError != nil {
				*warnings = append(*warnings, errors.WithMessage(err, "read from stdout failed").Error())
			}
		}
		done <- err
	}()

	// Make goroutine to check the progress every second.
	// Listening for channel doneProgress.
	if s.liveProgress != nil {
		go func() {
			type progress struct {
				TaskProgress []TaskProgress `xml:"taskprogress" json:"task_progress"`
			}
			p := &progress{}
			for {
				select {
				case <-doneProgress:
					close(s.liveProgress)
					return
				default:
					time.Sleep(time.Second)
					_ = xml.Unmarshal(stdout.Bytes(), p)
					if len(p.TaskProgress) > 0 {
						s.liveProgress <- p.TaskProgress[len(p.TaskProgress)-1].Percent
					}
				}
			}
		}()
	}

	// Check if function should run async.
	// When async process nmap result in goroutine that waits for nmap command finish.
	// Else block and process nmap result in this function scope.
	if s.doneAsync != nil {
		go func() {
			s.doneAsync <- s.processNmapResult(result, warnings, &stdout, &stderr, done, doneProgress)
		}()
	} else {
		err = s.processNmapResult(result, warnings, &stdout, &stderr, done, doneProgress)
	}

	return err
}

// AddOptions sets more scan options after the scan is created.
func (s *Scanner) AddOptions(options ...ArgOption) *Scanner {
	for _, option := range options {
		option(s)
	}
	return s
}

// Args return the list of nmap args
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

func (s *Scanner) processNmapResult(result *Run, warnings *[]string, stdout, stderr *bytes.Buffer, done chan error, doneProgress chan bool) error {
	// Wait for nmap to finish
	var err = <-done
	close(doneProgress)
	if err != nil {
		return err
	}

	// Check stderr output
	if err := checkStdErr(stderr, warnings); err != nil {
		return err
	}

	// Parse nmap xml output. Usually nmap always returns valid XML, even if there is a scan error.
	// Potentially available warnings are returned too, but probably not the reason for a broken XML.
	err = Parse(stdout.Bytes(), result)
	if err != nil {
		*warnings = append(*warnings, err.Error()) // Append parsing error to warnings for those who are interested.
		return ErrParseOutput
	}

	// Critical scan errors are reflected in the XML.
	if result != nil && len(result.Stats.Finished.ErrorMsg) > 0 {
		switch {
		case strings.Contains(result.Stats.Finished.ErrorMsg, "Error resolving name"):
			return ErrResolveName
		default:
			return fmt.Errorf(result.Stats.Finished.ErrorMsg)
		}
	}

	// Call filters if they are set.
	if s.portFilter != nil {
		choosePorts(result, s.portFilter)
	}
	if s.hostFilter != nil {
		chooseHosts(result, s.hostFilter)
	}

	return err
}

// checkStdErr will write the stderr to warnings array.
// It also processes nmap stderr output containing none-critical errors and warnings.
func checkStdErr(stderr *bytes.Buffer, warnings *[]string) error {
	if stderr.Len() <= 0 {
		return nil
	}

	stderrSplit := strings.Split(strings.Trim(stderr.String(), "\n "), "\n")

	// Check for warnings that will inevitably lead to parsing errors, hence, have priority.
	for _, warning := range stderrSplit {
		warning = strings.Trim(warning, " ")
		*warnings = append(*warnings, warning)
		switch {
		case strings.Contains(warning, "Malloc Failed!"):
			return ErrMallocFailed
		}
	}
	return nil
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

// WithBinaryPath sets the nmap binary path for a scanner.
func WithBinaryPath(binaryPath string) ArgOption {
	return func(s *Scanner) {
		s.binaryPath = binaryPath
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
