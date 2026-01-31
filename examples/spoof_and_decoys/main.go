package main

import (
	"context"
	"log"

	"github.com/Ullaakut/nmap/v4"
)

func main() {
	ctx := context.Background()

	scanner, err := nmap.NewScanner()
	if err != nil {
		log.Fatalf("creating nmap scanner: %v", err)
	}

	interfaceList, err := scanner.InterfaceList(ctx)
	if err != nil {
		log.Fatalf("getting interface list: %v", err)
	}

	if len(interfaceList.Interfaces) == 0 {
		log.Fatal("no interface to scan with")
	}

	lastInterfaceIndex := len(interfaceList.Interfaces) - 1
	interfaceToScan := interfaceList.Interfaces[lastInterfaceIndex].Device

	// Equivalent to
	// nmap -S 192.168.0.10 \
	// -D 192.168.0.2,192.168.0.3,192.168.0.4,192.168.0.5,192.168.0.6,ME,192.168.0.8 \
	// scanme.nmap.org`.
	scanner, err = nmap.NewScanner(
		nmap.WithInterface(interfaceToScan),
		nmap.WithTargets("scanme.nmap.org"),
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
		log.Fatalf("creating nmap scanner: %v", err)
	}

	log.Println("Running the following nmap command:", scanner.Args())

	result, err := scanner.Run(ctx)
	if err != nil {
		log.Fatalf("running network scan: %v", err)
	}

	warnings := result.Warnings()
	if len(warnings) > 0 {
		log.Printf("warning: %v\n", warnings) // Warnings are non-critical errors from nmap.
	}

	printResults(result)
}

func printResults(result *nmap.Run) {
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
