package main

import (
	"context"
	"log"

	"github.com/Ullaakut/nmap/v4"
)

func main() {
	scanner, err := nmap.NewScanner(
		nmap.WithIPv6Scanning(),
		nmap.WithConnectScan(),
		nmap.WithTargets("ipv6.google.com"),
		nmap.WithPorts("80,443"),
	)
	if err != nil {
		log.Fatalf("creating nmap scanner: %v", err)
	}

	_, err = scanner.Run(context.Background())
	if err != nil {
		log.Fatalf("running network scan: %v", err)
	}
}
