package nmap

import (
	"fmt"
	"time"
)

// Timing represents a timing template for nmap.
// These are meant to be used with the WithTimingTemplate method.
type Timing int16

const (
	// TimingSlowest also called paranoiac		NO PARALLELISM | 5min  timeout | 100ms to 10s    round-trip time timeout	| 5mn   scan delay
	TimingSlowest Timing = 0
	// TimingSneaky 							NO PARALLELISM | 15sec timeout | 100ms to 10s    round-trip time timeout	| 15s   scan delay
	TimingSneaky Timing = 1
	// TimingPolite 							NO PARALLELISM | 1sec  timeout | 100ms to 10s    round-trip time timeout	| 400ms scan delay
	TimingPolite Timing = 2
	// TimingNormal 							PARALLELISM	   | 1sec  timeout | 100ms to 10s    round-trip time timeout	| 0s    scan delay
	TimingNormal Timing = 3
	// TimingAggressive 						PARALLELISM	   | 500ms timeout | 100ms to 1250ms round-trip time timeout	| 0s    scan delay
	TimingAggressive Timing = 4
	// TimingFastest also called insane			PARALLELISM	   | 250ms timeout |  50ms to 300ms  round-trip time timeout	| 0s    scan delay
	TimingFastest Timing = 5
)

// WithTimingTemplate sets the timing template for nmap.
func WithTimingTemplate(timing Timing) Option {
	return func(s *Scanner) {
		s.args = append(s.args, fmt.Sprintf("-T%d", timing))
	}
}

// WithStatsEvery periodically prints a timing status message after each interval of time.
func WithStatsEvery(interval string) Option {
	return func(s *Scanner) {
		s.args = append(s.args, "--stats-every")
		s.args = append(s.args, interval)
	}
}

// WithMinHostgroup sets the minimal parallel host scan group size.
func WithMinHostgroup(size int) Option {
	return func(s *Scanner) {
		s.args = append(s.args, "--min-hostgroup")
		s.args = append(s.args, fmt.Sprint(size))
	}
}

// WithMaxHostgroup sets the maximal parallel host scan group size.
func WithMaxHostgroup(size int) Option {
	return func(s *Scanner) {
		s.args = append(s.args, "--max-hostgroup")
		s.args = append(s.args, fmt.Sprint(size))
	}
}

// WithMinParallelism sets the minimal number of parallel probes.
func WithMinParallelism(probes int) Option {
	return func(s *Scanner) {
		s.args = append(s.args, "--min-parallelism")
		s.args = append(s.args, fmt.Sprint(probes))
	}
}

// WithMaxParallelism sets the maximal number of parallel probes.
func WithMaxParallelism(probes int) Option {
	return func(s *Scanner) {
		s.args = append(s.args, "--max-parallelism")
		s.args = append(s.args, fmt.Sprint(probes))
	}
}

// WithMinRTTTimeout sets the minimal probe round trip time.
func WithMinRTTTimeout(roundTripTime time.Duration) Option {
	milliseconds := roundTripTime.Round(time.Nanosecond).Nanoseconds() / 1000000

	return func(s *Scanner) {
		s.args = append(s.args, "--min-rtt-timeout")
		s.args = append(s.args, fmt.Sprintf("%dms", int(milliseconds)))
	}
}

// WithMaxRTTTimeout sets the maximal probe round trip time.
func WithMaxRTTTimeout(roundTripTime time.Duration) Option {
	milliseconds := roundTripTime.Round(time.Nanosecond).Nanoseconds() / 1000000

	return func(s *Scanner) {
		s.args = append(s.args, "--max-rtt-timeout")
		s.args = append(s.args, fmt.Sprintf("%dms", int(milliseconds)))
	}
}

// WithInitialRTTTimeout sets the initial probe round trip time.
func WithInitialRTTTimeout(roundTripTime time.Duration) Option {
	milliseconds := roundTripTime.Round(time.Nanosecond).Nanoseconds() / 1000000

	return func(s *Scanner) {
		s.args = append(s.args, "--initial-rtt-timeout")
		s.args = append(s.args, fmt.Sprintf("%dms", int(milliseconds)))
	}
}

// WithMaxRetries sets the maximal number of port scan probe retransmissions.
func WithMaxRetries(tries int) Option {
	return func(s *Scanner) {
		s.args = append(s.args, "--max-retries")
		s.args = append(s.args, fmt.Sprint(tries))
	}
}

// WithHostTimeout sets the time after which nmap should give up on a target host.
func WithHostTimeout(timeout time.Duration) Option {
	milliseconds := timeout.Round(time.Nanosecond).Nanoseconds() / 1000000

	return func(s *Scanner) {
		s.args = append(s.args, "--host-timeout")
		s.args = append(s.args, fmt.Sprintf("%dms", int(milliseconds)))
	}
}

// WithScanDelay sets the minimum time to wait between each probe sent to a host.
func WithScanDelay(timeout time.Duration) Option {
	milliseconds := timeout.Round(time.Nanosecond).Nanoseconds() / 1000000

	return func(s *Scanner) {
		s.args = append(s.args, "--scan-delay")
		s.args = append(s.args, fmt.Sprintf("%dms", int(milliseconds)))
	}
}

// WithMaxScanDelay sets the maximum time to wait between each probe sent to a host.
func WithMaxScanDelay(timeout time.Duration) Option {
	milliseconds := timeout.Round(time.Nanosecond).Nanoseconds() / 1000000

	return func(s *Scanner) {
		s.args = append(s.args, "--max-scan-delay")
		s.args = append(s.args, fmt.Sprintf("%dms", int(milliseconds)))
	}
}

// WithMinRate sets the minimal number of packets sent per second.
func WithMinRate(packetsPerSecond int) Option {
	return func(s *Scanner) {
		s.args = append(s.args, "--min-rate")
		s.args = append(s.args, fmt.Sprint(packetsPerSecond))
	}
}

// WithMaxRate sets the maximal number of packets sent per second.
func WithMaxRate(packetsPerSecond int) Option {
	return func(s *Scanner) {
		s.args = append(s.args, "--max-rate")
		s.args = append(s.args, fmt.Sprint(packetsPerSecond))
	}
}
