package main

import (
	"context"
	"log"

	"github.com/Ullaakut/nmap/v4"
)

func main() {
	scanner, err := nmap.NewScanner(
		nmap.WithTargets("scanme.nmap.org"),
		nmap.WithPorts("22,80,443"),
		nmap.WithOSDetection(),
		nmap.WithServiceInfo(),
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

		log.Printf("Host %q", host.Addresses[0])
		if len(host.OS.Matches) > 0 {
			match := host.OS.Matches[0]
			log.Printf("OS guess: %s (%d%%)", match.Name, match.Accuracy)
		}

		for _, port := range host.Ports {
			log.Printf("Port %d/%s %s %s", port.ID, port.Protocol, port.State, port.Service.Name)
		}
	}
}
