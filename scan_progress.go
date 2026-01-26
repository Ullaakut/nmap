package nmap

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
)

func (s *Scanner) runAndParseWithProgress(ctx context.Context, cmd *exec.Cmd) (*Run, error) {
	var stdout, stderr bytes.Buffer
	cmd.Stderr = &stderr

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}

	err = cmd.Start()
	if err != nil {
		return nil, err
	}

	readErrCh := make(chan error, 1)
	go func() {
		tee := io.TeeReader(stdoutPipe, &stdout)
		readErrCh <- streamTaskProgress(tee, s.progressHandler)
	}()

	runErr := cmd.Wait()
	readErr := <-readErrCh

	result, parseErr := s.processNmapResult(&stdout, &stderr)
	if readErr != nil && !errors.Is(readErr, io.EOF) && result != nil {
		result.warnings = append(result.warnings, fmt.Sprintf("progress stream error: %s", readErr))
	}

	return finalizeRun(ctx, runErr, parseErr, result, &stdout, &stderr)
}
