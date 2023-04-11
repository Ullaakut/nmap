package main

import (
	"context"
	"fmt"
	"log"

	"github.com/Ullaakut/nmap/v2"
)

func main() {
	// Equivalent to
	// nmap -e eth0 -S 192.168.0.10 \
	// -D 192.168.0.2,192.168.0.3,192.168.0.4,192.168.0.5,192.168.0.6,ME,192.168.0.8 \
	// 192.168.0.72`.
	scanner, err := nmap.NewScanner(
		context.Background(),
		nmap.WithInterface("eth0"),
		nmap.WithTargets("192.168.0.72"),
		nmap.WithSpoofIPAddress("192.168.0.10"),
		nmap.WithDecoys(
			"192.168.0.2",
			"192.168.0.3",
			"192.168.0.4",
			"192.168.0.5",
			"192.168.0.6",
			"ME",
			"192.168.0.8",
		),
	)
	if err != nil {
		log.Fatalf("unable to create nmap scanner: %v", err)
	}

	fmt.Println("Running the following nmap command:", scanner.Args())

	var result nmap.Run
	var warnings []string
	err = scanner.Run(&result, &warnings)
	if err != nil {
		log.Fatalf("nmap scan failed: %v", err)
	}

	printResults(&result)
}

func printResults(result *nmap.Run) {
	// Use the results to print an example output
	for _, host := range result.Hosts {
		if len(host.Ports) == 0 || len(host.Addresses) == 0 {
			continue
		}

		fmt.Printf("Host %q:\n", host.Addresses[0])

		for _, port := range host.Ports {
			fmt.Printf("\tPort %d/%s %s %s\n", port.ID, port.Protocol, port.State, port.Service.Name)
		}
	}

	fmt.Printf("Nmap done: %d hosts up scanned in %.2f seconds\n", len(result.Hosts), result.Stats.Finished.Elapsed)
}
