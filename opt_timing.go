package nmap

import (
	"fmt"
	"strconv"
	"time"
)

// Timing represents a timing template for nmap.
// These are meant to be used with the WithTimingTemplate method.
type Timing int16

const (
	// TimingSlowest also called paranoiac		NO PARALLELISM | 5min  timeout | 100ms to 10s    round-trip time timeout	| 5mn   scan delay.
	TimingSlowest Timing = 0
	// TimingSneaky 							NO PARALLELISM | 15sec timeout | 100ms to 10s    round-trip time timeout	| 15s   scan delay.
	TimingSneaky Timing = 1
	// TimingPolite 							NO PARALLELISM | 1sec  timeout | 100ms to 10s    round-trip time timeout	| 400ms scan delay.
	TimingPolite Timing = 2
	// TimingNormal 							PARALLELISM	   | 1sec  timeout | 100ms to 10s    round-trip time timeout	| 0s    scan delay.
	TimingNormal Timing = 3
	// TimingAggressive 						PARALLELISM	   | 500ms timeout | 100ms to 1250ms round-trip time timeout	| 0s    scan delay.
	TimingAggressive Timing = 4
	// TimingFastest also called insane			PARALLELISM	   | 250ms timeout |  50ms to 300ms  round-trip time timeout	| 0s    scan delay.
	TimingFastest Timing = 5
)

// WithTimingTemplate sets the timing template for nmap.
func WithTimingTemplate(timing Timing) Option {
	return func(s *Scanner) error {
		s.args = append(s.args, fmt.Sprintf("-T%d", timing))
		return nil
	}
}

// WithMinHostgroup sets the minimal parallel host scan group size.
func WithMinHostgroup(size int) Option {
	return func(s *Scanner) error {
		s.args = append(s.args, "--min-hostgroup")
		s.args = append(s.args, strconv.Itoa(size))
		return nil
	}
}

// WithMaxHostgroup sets the maximal parallel host scan group size.
func WithMaxHostgroup(size int) Option {
	return func(s *Scanner) error {
		s.args = append(s.args, "--max-hostgroup")
		s.args = append(s.args, strconv.Itoa(size))
		return nil
	}
}

// WithMinParallelism sets the minimal number of parallel probes.
func WithMinParallelism(probes int) Option {
	return func(s *Scanner) error {
		s.args = append(s.args, "--min-parallelism")
		s.args = append(s.args, strconv.Itoa(probes))
		return nil
	}
}

// WithMaxParallelism sets the maximal number of parallel probes.
func WithMaxParallelism(probes int) Option {
	return func(s *Scanner) error {
		s.args = append(s.args, "--max-parallelism")
		s.args = append(s.args, strconv.Itoa(probes))
		return nil
	}
}

// WithMinRTTTimeout sets the minimal probe round trip time.
func WithMinRTTTimeout(roundTripTime time.Duration) Option {
	return func(s *Scanner) error {
		formatted, err := formatNmapDuration(roundTripTime)
		if err != nil {
			return fmt.Errorf("format round trip time: %w", err)
		}

		s.args = append(s.args, "--min-rtt-timeout")
		s.args = append(s.args, formatted)
		return nil
	}
}

// WithMaxRTTTimeout sets the maximal probe round trip time.
func WithMaxRTTTimeout(roundTripTime time.Duration) Option {
	return func(s *Scanner) error {
		formatted, err := formatNmapDuration(roundTripTime)
		if err != nil {
			return fmt.Errorf("format round trip time: %w", err)
		}

		s.args = append(s.args, "--max-rtt-timeout")
		s.args = append(s.args, formatted)
		return nil
	}
}

// WithInitialRTTTimeout sets the initial probe round trip time.
func WithInitialRTTTimeout(roundTripTime time.Duration) Option {
	return func(s *Scanner) error {
		formatted, err := formatNmapDuration(roundTripTime)
		if err != nil {
			return fmt.Errorf("format round trip time: %w", err)
		}

		s.args = append(s.args, "--initial-rtt-timeout")
		s.args = append(s.args, formatted)
		return nil
	}
}

// WithMaxRetries sets the maximal number of port scan probe retransmissions.
func WithMaxRetries(tries int) Option {
	return func(s *Scanner) error {
		s.args = append(s.args, "--max-retries")
		s.args = append(s.args, strconv.Itoa(tries))
		return nil
	}
}

// WithHostTimeout sets the time after which nmap should give up on a target host.
func WithHostTimeout(timeout time.Duration) Option {
	return func(s *Scanner) error {
		formatted, err := formatNmapDuration(timeout)
		if err != nil {
			return fmt.Errorf("format host timeout: %w", err)
		}

		s.args = append(s.args, "--host-timeout")
		s.args = append(s.args, formatted)
		return nil
	}
}

// WithScanDelay sets the minimum time to wait between each probe sent to a host.
func WithScanDelay(delay time.Duration) Option {
	return func(s *Scanner) error {
		formatted, err := formatNmapDuration(delay)
		if err != nil {
			return fmt.Errorf("format scan delay: %w", err)
		}

		s.args = append(s.args, "--scan-delay")
		s.args = append(s.args, formatted)
		return nil
	}
}

// WithMaxScanDelay sets the maximum time to wait between each probe sent to a host.
func WithMaxScanDelay(delay time.Duration) Option {
	return func(s *Scanner) error {
		formatted, err := formatNmapDuration(delay)
		if err != nil {
			return fmt.Errorf("format scan delay: %w", err)
		}

		s.args = append(s.args, "--max-scan-delay")
		s.args = append(s.args, formatted)
		return nil
	}
}

// WithMinRate sets the minimal number of packets sent per second.
func WithMinRate(packetsPerSecond int) Option {
	return func(s *Scanner) error {
		s.args = append(s.args, "--min-rate")
		s.args = append(s.args, strconv.Itoa(packetsPerSecond))
		return nil
	}
}

// WithMaxRate sets the maximal number of packets sent per second.
func WithMaxRate(packetsPerSecond int) Option {
	return func(s *Scanner) error {
		s.args = append(s.args, "--max-rate")
		s.args = append(s.args, strconv.Itoa(packetsPerSecond))
		return nil
	}
}

func formatNmapDuration(duration time.Duration) (string, error) {
	if duration < 0 {
		return "", fmt.Errorf("duration must be non-negative, got %s", duration)
	}
	if duration == 0 {
		return "0s", nil
	}
	if duration%time.Millisecond != 0 {
		return "", fmt.Errorf("duration must be a multiple of 1ms, got %s", duration)
	}

	switch {
	case duration%time.Hour == 0:
		return fmt.Sprintf("%dh", duration/time.Hour), nil
	case duration%time.Minute == 0:
		return fmt.Sprintf("%dm", duration/time.Minute), nil
	case duration%time.Second == 0:
		return fmt.Sprintf("%ds", duration/time.Second), nil
	default:
		return fmt.Sprintf("%dms", duration/time.Millisecond), nil
	}
}
