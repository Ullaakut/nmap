package main

import (
	"context"
	"log"

	"github.com/Ullaakut/nmap/v4"
)

func main() {
	scanner, err := nmap.NewScanner(
		nmap.WithTargets("scanme.nmap.org"),
		nmap.WithPorts("80,443"),
		nmap.WithNmapOutput("scan.txt"),
		nmap.WithGrepOutput("scan.gnmap"),
	)
	if err != nil {
		log.Fatalf("creating nmap scanner: %v", err)
	}

	scanner, err = scanner.ToFile("scan.xml")
	if err != nil {
		log.Fatalf("enabling xml output: %v", err)
	}

	_, err = scanner.Run(context.Background())
	if err != nil {
		log.Fatalf("running network scan: %v", err)
	}
}
