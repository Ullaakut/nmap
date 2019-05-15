package main

import (
	"fmt"
	"log"

	"github.com/Ullaakut/nmap"
	osfamily "github.com/Ullaakut/nmap/pkg/osfamilies"
)

func main() {
	// Equivalent to
	// nmap -F -O 192.168.0.0/24
	scanner, err := nmap.NewScanner(
		nmap.WithTargets("192.168.0.0/24"),
		nmap.WithFastMode(),
		nmap.WithOSDetection(),
	)
	if err != nil {
		log.Fatalf("unable to create nmap scanner: %v", err)
	}

	result, err := scanner.Run()
	if err != nil {
		log.Fatalf("nmap scan failed: %v", err)
	}

	countByOS(result)
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
