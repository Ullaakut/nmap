package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/Ullaakut/nmap/v3"
)

func main() {
	scanner, err := nmap.NewScanner(
		context.Background(),
		nmap.WithTargets("localhost"),
		nmap.WithPorts("1-4000"),
		nmap.WithServiceInfo(),
		nmap.WithVerbosity(3),
	)
	if err != nil {
		log.Fatalf("unable to create nmap scanner: %v", err)
	}

	result, warnings, err := scanner.Streamer(os.Stdout).Run()
	if len(warnings) > 0 {
		log.Printf("run finished with warnings: %s\n", warnings) // Warnings are non-critical errors from nmap.
	}
	if err != nil {
		log.Fatalf("unable to run nmap scan: %v", err)
	}

	fmt.Printf("Nmap done: %d hosts up scanned in %.2f seconds\n", len(result.Hosts), result.Stats.Finished.Elapsed)
}
