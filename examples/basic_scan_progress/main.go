package main

import (
	"fmt"
	"github.com/Ullaakut/nmap/v2"
	"log"
	"time"
)

func main() {
	scanner, err := nmap.NewScanner(
		nmap.WithTargets("localhost"),
		nmap.WithPorts("1-4000"),
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

	result, _, err := scanner.RunWithProgress(progress)
	if err != nil {
		log.Fatalf("unable to run nmap scan: %v", err)
	}

	time.Sleep(2 * time.Second)

	fmt.Printf("Nmap done: %d hosts up scanned in %.2f seconds\n", len(result.Hosts), result.Stats.Finished.Elapsed)
}
