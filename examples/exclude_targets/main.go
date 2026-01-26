package main

import (
	"context"
	"log"

	"github.com/Ullaakut/nmap/v4"
)

func main() {
	scanner, err := nmap.NewScanner(
		nmap.WithTargets("192.168.1.0/24"),
		nmap.WithTargetExclusions("192.168.1.10", "192.168.1.11"),
		nmap.WithPorts("22,80"),
	)
	if err != nil {
		log.Fatalf("creating nmap scanner: %v", err)
	}

	_, err = scanner.Run(context.Background())
	if err != nil {
		log.Fatalf("running network scan: %v", err)
	}
}
