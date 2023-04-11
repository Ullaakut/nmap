package main

import (
	"context"
	"fmt"
	"github.com/Ullaakut/nmap/v3"
	"log"
	"os"
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

	var result nmap.Run
	var warnings []string
	err = scanner.Streamer(os.Stdout).Run(&result, &warnings)
	if err != nil {
		log.Fatalf("unable to run nmap scan: %v", err)
	}

	fmt.Printf("Nmap warnings: %v\n", warnings)

	fmt.Printf("Nmap done: %d hosts up scanned in %.2f seconds\n", len(result.Hosts), result.Stats.Finished.Elapsed)
}
