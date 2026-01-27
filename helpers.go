package nmap

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

func (s *Scanner) buildArgs() []string {
	args := append([]string{}, s.args...)

	// Write XML to standard output by default.
	// If toFile is set then write XML to file.
	outArg := "-"
	if s.toFile != nil {
		outArg = *s.toFile
	}
	args = append(args, "-oX", outArg)

	return args
}

func (s *Scanner) newCmd(ctx context.Context) *exec.Cmd {
	args := s.buildArgs()

	//nolint:gosec // Arguments are passed directly to nmap; users intentionally control args.
	cmd := exec.CommandContext(ctx, s.binaryPath, args...)
	if s.modifySysProcAttr != nil {
		s.modifySysProcAttr(cmd.SysProcAttr)
	}
	return cmd
}

func finalizeRun(ctx context.Context, runErr, parseErr error, result *Run, stdout, stderr *bytes.Buffer) (*Run, error) {
	if runErr == nil {
		return result, parseErr
	}

	mappedErr := mapRunError(ctx, runErr)
	if mappedErr != nil {
		return result, mappedErr
	}

	if parseErr != nil {
		if stdout.Len() == 0 && stderr.Len() == 0 {
			return result, nil
		}
		return result, parseErr
	}
	return result, mappedErr
}

func streamTaskProgress(reader io.Reader, handler func(TaskProgress)) error {
	decoder := xml.NewDecoder(reader)
	for {
		token, err := decoder.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		start, ok := token.(xml.StartElement)
		if !ok || start.Name.Local != "taskprogress" {
			continue
		}

		var progress TaskProgress
		err = decoder.DecodeElement(&progress, &start)
		if err != nil {
			return err
		}
		handler(progress)
	}
}

type channelWriter struct {
	ch chan<- []byte
}

func (w channelWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	chunk := make([]byte, len(p))
	copy(chunk, p)
	w.ch <- chunk
	return len(p), nil
}

func (s *Scanner) processNmapResult(stdout, stderr *bytes.Buffer) (*Run, error) {
	result := &Run{}

	// Check for errors indicated by stderr output.
	var warnings []string
	warnings, errStdout := checkStdErr(stderr)
	if errStdout != nil {
		return result, errStdout
	}

	contents := stdout.Bytes()

	// Parse nmap xml output. Usually nmap always returns valid XML, even if there is a scan error.
	// Potentially available warnings are returned too, but probably not the reason for a broken XML.
	var err error
	if s.toFile != nil {
		contents, err = os.ReadFile(*s.toFile)
		if err != nil {
			return result, fmt.Errorf("reading output file %s: %w", *s.toFile, err)
		}

		if chmodErr := os.Chmod(*s.toFile, 0o600); chmodErr != nil {
			warnings = append(warnings, fmt.Sprintf("unable to set output file permissions: %s", chmodErr))
		}
	}

	result, err = parse(contents)
	if err != nil {
		return nil, fmt.Errorf("parsing nmap XML output: %w", err)
	}

	// Add warnings after parsing to avoid them being overwritten.
	result.warnings = append(result.warnings, warnings...)

	// Critical scan errors are reflected in the XML.
	if len(result.Stats.Finished.ErrorMsg) > 0 {
		switch {
		case strings.Contains(result.Stats.Finished.ErrorMsg, "Error resolving name"):
			return result, ErrResolveName
		default:
			return result, errors.New(result.Stats.Finished.ErrorMsg)
		}
	}

	// Call filters if they are set.
	if s.portFilter != nil {
		choosePorts(result, s.portFilter)
	}
	if s.hostFilter != nil {
		chooseHosts(result, s.hostFilter)
	}

	return result, nil
}

func mapRunError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}

	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return ErrScanTimeout
	case errors.Is(ctx.Err(), context.Canceled):
		return ErrScanInterrupt
	case isInterruptExit(err):
		return ErrScanInterrupt
	default:
		return err
	}
}

func isInterruptExit(err error) bool {
	if err == nil {
		return false
	}

	switch err.Error() {
	case "exit status 0xc000013a": // Exit code for ctrl+c on Windows
		return true
	case "exit status 130": // Exit code for ctrl+c on Linux
		return true
	default:
		return false
	}
}

// checkStdErr writes the output of stderr to the warnings array.
// It also processes nmap stderr output containing none-critical errors and warnings.
func checkStdErr(stderr *bytes.Buffer) (warnings []string, err error) {
	if stderr.Len() <= 0 {
		return nil, nil
	}

	stderrSplit := strings.SplitSeq(strings.Trim(stderr.String(), "\n "), "\n")

	// Check for warnings that inevitably lead to parsing errors, hence, have priority.
	for warning := range stderrSplit {
		warning = strings.Trim(warning, " ")
		warnings = append(warnings, warning)
		switch {
		case strings.Contains(warning, "Malloc Failed!"):
			return warnings, ErrMallocFailed
		case strings.Contains(warning, "requires root privileges."):
			return warnings, ErrRequiresRoot
		default:
		}
	}
	return warnings, nil
}
