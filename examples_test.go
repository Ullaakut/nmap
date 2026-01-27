package nmap

import (
	"context"
	"fmt"
	"log"
)

// A scanner can be instantiated with options to set the arguments
// that are given to nmap.
func ExampleScanner_simple() {
	s, err := NewScanner(
		WithTargets("google.com", "facebook.com", "youtube.com"),
		WithCustomDNSServers("8.8.8.8", "8.8.4.4"),
		WithTimingTemplate(TimingFastest),
		WithTCPScanFlags(FlagACK, FlagNULL, FlagRST),
	)
	if err != nil {
		log.Fatalf("creating nmap scanner: %v", err)
	}

	scanResult, err := s.Run(context.Background())
	if err != nil {
		log.Fatalf("running network scan: %v", err)
	}

	fmt.Printf(
		"Scan successful: %d hosts up\n",
		scanResult.Stats.Hosts.Up,
	)
	// Output: Scan successful: 3 hosts up
}
