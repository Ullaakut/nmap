package main

import (
	"fmt"
	"log"

	"github.com/Ullaakut/nmap/v2"
)

func main() {
	scanner, err := nmap.NewScanner(
		nmap.WithTargets("localhost"),
		nmap.WithPorts("1-10000"),
		nmap.WithServiceInfo(),
		nmap.WithVerbosity(3),
	)
	if err != nil {
		log.Fatalf("unable to create nmap scanner: %v", err)
	}

	progress := make(chan float32, 1)

	// Function to listen and print the progress
	go func() {
		for p := range progress {
			fmt.Printf("Progress: %v %%\n", p)
		}
	}()

	var result nmap.Run
	var warnings []string
	err = scanner.Progress(progress).Run(&result, &warnings)
	if err != nil {
		log.Fatalf("unable to run nmap scan: %v", err)
	}

	fmt.Printf("Nmap done: %d hosts up scanned in %.2f seconds\n", len(result.Hosts), result.Stats.Finished.Elapsed)
}
