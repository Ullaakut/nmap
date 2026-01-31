package nmap

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
)

func (s *Scanner) runAsync(ctx context.Context) (<-chan []byte, <-chan []byte, <-chan RunResult, error) {
	cmd := s.newCmd(ctx)

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, nil, err
	}

	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return nil, nil, nil, err
	}

	err = cmd.Start()
	if err != nil {
		return nil, nil, nil, err
	}

	stdoutCh := make(chan []byte, 16)
	stderrCh := make(chan []byte, 16)
	resultCh := make(chan RunResult, 1)

	var stdout, stderr bytes.Buffer
	stdoutWriter := io.MultiWriter(&stdout, channelWriter{ch: stdoutCh})
	stderrWriter := io.MultiWriter(&stderr, channelWriter{ch: stderrCh})

	stdoutErrCh := make(chan error, 1)
	stderrErrCh := make(chan error, 1)

	// Start goroutine to read stdout.
	go func() {
		defer close(stdoutCh)

		// If progress handler is set, stream progress updates.
		if s.progressHandler != nil {
			tee := io.TeeReader(stdoutPipe, stdoutWriter)
			stdoutErrCh <- streamTaskProgress(tee, s.progressHandler)
			return
		}
		_, copyErr := io.Copy(stdoutWriter, stdoutPipe)
		stdoutErrCh <- copyErr
	}()

	// Start goroutine to read stderr.
	go func() {
		defer close(stderrCh)
		_, copyErr := io.Copy(stderrWriter, stderrPipe)
		stderrErrCh <- copyErr
	}()

	// Start goroutine to wait for nmap to finish and process the result.
	go func() {
		defer close(resultCh)

		runErr := cmd.Wait()
		stdoutErr := <-stdoutErrCh
		stderrErr := <-stderrErrCh

		result, parseErr := s.processNmapResult(&stdout, &stderr)
		if stdoutErr != nil && !errors.Is(stdoutErr, io.EOF) && result != nil {
			result.warnings = append(result.warnings, fmt.Sprintf("stdout stream error: %s", stdoutErr))
		}
		if stderrErr != nil && !errors.Is(stderrErr, io.EOF) && result != nil {
			result.warnings = append(result.warnings, fmt.Sprintf("stderr stream error: %s", stderrErr))
		}

		finalResult, finalErr := finalizeRun(ctx, runErr, parseErr, result, &stdout, &stderr)
		resultCh <- RunResult{Result: finalResult, Err: finalErr}
	}()

	return stdoutCh, stderrCh, resultCh, nil
}
