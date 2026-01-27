package nmap

import (
	"bytes"
	"context"
	"os/exec"
)

func (s *Scanner) runAndParse(ctx context.Context, cmd *exec.Cmd) (*Run, error) {
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	result, parseErr := s.processNmapResult(&stdout, &stderr)
	return finalizeRun(ctx, runErr, parseErr, result, &stdout, &stderr)
}
