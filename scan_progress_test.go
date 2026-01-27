package nmap

import (
	"os"
	"sync"
	"testing"
	"time"

	isatty "github.com/mattn/go-isatty"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunWithProgress(t *testing.T) {
	var (
		mu         sync.Mutex
		progresses []TaskProgress
	)

	if !isatty.IsTerminal(os.Stdout.Fd()) {
		t.Skip("skipping progress test since not running in a TTY")
	}

	handler := func(p TaskProgress) {
		mu.Lock()
		progresses = append(progresses, p)
		mu.Unlock()
	}

	s, err := NewScanner(
		WithTargets("localhost"),
		WithPorts("1-1024"),
		WithTimingTemplate(TimingNormal),
		WithProgress(time.Second, handler),
		WithScanDelay(10*time.Millisecond),
	)
	require.NoError(t, err)

	ctx := t.Context()
	result, err := s.Run(ctx)
	require.NoError(t, err)

	mu.Lock()
	count := len(progresses)
	var last TaskProgress
	if count > 0 {
		last = progresses[count-1]
	}
	mu.Unlock()

	require.Greater(t, count, 0, "expected at least one progress update")
	assert.InDelta(t, 100, last.Percent, 10.0)

	require.NotNil(t, result)
	assert.Equal(t, "nmap", result.Scanner)
}
