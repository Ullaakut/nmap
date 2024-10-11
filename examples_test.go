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
		context.Background(),
		WithTargets("google.com", "facebook.com", "youtube.com"),
		WithCustomDNSServers("8.8.8.8", "8.8.4.4"),
		WithTimingTemplate(TimingFastest),
		WithTCPScanFlags(FlagACK, FlagNULL, FlagRST),
	)
	if err != nil {
		log.Fatalf("unable to create nmap scanner: %v", err)
	}

	scanResult, _, err := s.Run()
	if err != nil {
		log.Fatalf("nmap encountered an error: %v", err)
	}

	fmt.Printf(
		"Scan successful: %d hosts up\n",
		scanResult.Stats.Hosts.Up,
	)
	// Output: Scan successful: 3 hosts up
}
