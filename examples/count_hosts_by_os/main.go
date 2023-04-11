package main

import (
	"context"
	"fmt"
	"log"

	"github.com/Ullaakut/nmap/v3"
	osfamily "github.com/Ullaakut/nmap/v3/pkg/osfamilies"
)

func main() {
	// Equivalent to
	// nmap -F -O 192.168.0.0/24
	scanner, err := nmap.NewScanner(
		context.Background(),
		nmap.WithTargets("192.168.0.0/24"),
		nmap.WithFastMode(),
		nmap.WithOSDetection(), // Needs to run with sudo
	)
	if err != nil {
		log.Fatalf("unable to create nmap scanner: %v", err)
	}

	var result nmap.Run
	var warnings []string
	err = scanner.Run(&result, &warnings)
	if err != nil {
		log.Fatalf("nmap scan failed: %v", err)
	}

	countByOS(&result)
}

func countByOS(result *nmap.Run) {
	var (
		linux, windows int
	)

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

	fmt.Printf("Discovered %d linux hosts and %d windows hosts out of %d total up hosts.\n", linux, windows, result.Stats.Hosts.Up)
}
