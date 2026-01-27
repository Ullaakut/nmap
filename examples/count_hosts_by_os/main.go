package main

import (
	"context"
	"log"

	"github.com/Ullaakut/nmap/v4"
	osfamily "github.com/Ullaakut/nmap/v4/pkg/osfamilies"
)

func main() {
	// Equivalent to
	// nmap -F -O scanme.nmap.org
	scanner, err := nmap.NewScanner(
		nmap.WithTargets("scanme.nmap.org"),
		nmap.WithFastMode(),
		nmap.WithOSDetection(), // Needs to run with sudo
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

	countByOS(result)
}

func countByOS(result *nmap.Run) {
	var linux, windows int

	// Count the number of each OS for all hosts.
	for _, host := range result.Hosts {
		for _, match := range host.OS.Matches {
			for _, class := range match.Classes {
				switch class.OSFamily() {
				case osfamily.Linux:
					linux++
				case osfamily.Windows:
					windows++
				}
			}
		}
	}

	log.Printf("Discovered %d linux hosts and %d windows hosts out of %d total up hosts.\n", linux, windows, result.Stats.Hosts.Up)
}
