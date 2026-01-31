package main

import (
	"context"
	"log"

	"github.com/Ullaakut/nmap/v4"
)

func main() {
	// Equivalent to
	// nmap -sV -T4 scanme.nmap.org with a filter to remove hosts without open ports.
	scanner, err := nmap.NewScanner(
		nmap.WithTargets("scanme.nmap.org"),
		nmap.WithPorts("22", "80", "443"),
		nmap.WithServiceInfo(),
		nmap.WithTimingTemplate(nmap.TimingAggressive),
		// Filter out hosts that don't have any open ports
		nmap.WithFilterHost(func(h nmap.Host) bool {
			// Filter out hosts with no open ports.
			for idx := range h.Ports {
				if h.Ports[idx].Status() == "open" {
					return true
				}
			}

			return false
		}),
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

	for _, host := range result.Hosts {
		log.Printf("Host %s\n", host.Addresses[0])

		for _, port := range host.Ports {
			if port.Status() != "open" {
				continue
			}

			log.Printf("\tPort %d open (%s)\n", port.ID, port.Service.Name)
		}
	}
}
