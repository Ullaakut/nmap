package nmap

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/hamba/testutils/retry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunAsync(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	s, err := NewScanner(
		WithTargets("localhost"),
		WithPorts("1-1024"),
		WithTimingTemplate(TimingNormal),
	)
	require.NoError(t, err)

	stdoutCh, stderrCh, resultCh, err := s.RunAsync(ctx)
	require.NoError(t, err)

	var stdoutBuf bytes.Buffer
	var stderrBuf bytes.Buffer
	stdoutDone := make(chan struct{})
	stderrDone := make(chan struct{})

	go func() {
		defer close(stdoutDone)
		for chunk := range stdoutCh {
			_, _ = stdoutBuf.Write(chunk)
		}
	}()

	go func() {
		defer close(stderrDone)
		for chunk := range stderrCh {
			_, _ = stderrBuf.Write(chunk)
		}
	}()

	var runResult RunResult
	var gotResult bool

	retry.RunWith(t, retry.NewTimer(10*time.Second, time.Second), func(r *retry.SubT) {
		if !gotResult {
			select {
			case rr, ok := <-resultCh:
				if ok {
					runResult = rr
					gotResult = true
				}
			default:
			}
		}

		require.True(r, gotResult, "expected async result")
		require.NoError(r, runResult.Err)
		require.NotNil(r, runResult.Result)
		assert.Equal(r, "nmap", runResult.Result.Scanner)
	})

	<-stdoutDone
	<-stderrDone

	assert.Greater(t, stdoutBuf.Len(), 0)
	if stderrBuf.Len() > 0 {
		t.Logf("stderr: %s", stderrBuf.String())
	}
}
