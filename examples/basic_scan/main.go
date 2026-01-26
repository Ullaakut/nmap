package main

import (
	"context"
	"log"

	"github.com/Ullaakut/nmap/v4"
)

func main() {
	// Equivalent to `/usr/local/bin/nmap -p 80,443,843 scanme.nmap.org`,
	// with a 5-minute timeout.
	scanner, err := nmap.NewScanner(
		nmap.WithTargets("scanme.nmap.org"),
		nmap.WithPorts("80,443,843"),
	)
	if err != nil {
		log.Fatalf("creating nmap scanner: %v", err)
	}

	result, err := scanner.Run(context.Background())
	if err != nil {
		log.Fatalf("running network scan: %v", err)
	}

	warnings := result.Warnings()
	if len(warnings) > 0 {
		log.Printf("warning: %v\n", warnings) // Warnings are non-critical errors from nmap.
	}

	// Use the results to print an example output
	for _, host := range result.Hosts {
		if len(host.Ports) == 0 || len(host.Addresses) == 0 {
			continue
		}

		log.Printf("Host %q:\n", host.Addresses[0])

		for _, port := range host.Ports {
			log.Printf("\tPort %d/%s %s %s\n", port.ID, port.Protocol, port.State, port.Service.Name)
		}
	}

	log.Printf("Nmap done: %d hosts up scanned in %.2f seconds\n", len(result.Hosts), result.Stats.Finished.Elapsed)
}
