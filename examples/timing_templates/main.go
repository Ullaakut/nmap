package main

import (
	"context"
	"log"
	"time"

	"github.com/Ullaakut/nmap/v4"
)

func main() {
	scanner, err := nmap.NewScanner(
		nmap.WithTargets("scanme.nmap.org"),
		nmap.WithPorts("1-1024"),
		nmap.WithTimingTemplate(nmap.TimingAggressive),
		nmap.WithScanDelay(10*time.Millisecond),
		nmap.WithMaxRetries(2),
	)
	if err != nil {
		log.Fatalf("creating nmap scanner: %v", err)
	}

	result, err := scanner.Run(context.Background())
	if err != nil {
		log.Fatalf("running network scan: %v", err)
	}

	for _, host := range result.Hosts {
		if len(host.Addresses) == 0 {
			continue
		}

		log.Printf("%s is %s", host.Addresses[0], host.Status.State)
	}
}
