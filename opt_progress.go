package nmap

import (
	"errors"
	"fmt"
	"time"
)

// WithProgress enables live progress updates by parsing <taskprogress> elements
// from the XML stream. The interval controls nmap's --stats-every option.
//
// NOTE: progress updates require XML output on stdout. Using ToFile disables
// the live progress stream.
func WithProgress(interval time.Duration, handler func(TaskProgress)) Option {
	return func(s *Scanner) error {
		if handler == nil {
			return errors.New("progress handler must not be nil")
		}
		if s.toFile != nil {
			return errors.New("progress updates require XML on stdout; do not use WithProgress with ToFile")
		}
		if !s.interactive {
			return errors.New("progress updates require interactive terminal; cannot use WithProgress in non-interactive mode")
		}

		formatted, err := formatNmapDuration(interval)
		if err != nil {
			return fmt.Errorf("format progress interval: %w", err)
		}

		s.args = append(s.args, "--stats-every", formatted)
		s.progressHandler = handler
		return nil
	}
}
