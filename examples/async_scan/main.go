package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/Ullaakut/nmap/v4"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	scanner, err := nmap.NewScanner(
		nmap.WithTargets("scanme.nmap.org"),
		nmap.WithPorts("1-1024"),
	)
	if err != nil {
		log.Fatalf("creating nmap scanner: %v", err)
	}

	stdout, stderr, resultCh, err := scanner.RunAsync(ctx)
	if err != nil {
		log.Fatalf("running network scan: %v", err)
	}

	for {
		select {
		case <-ctx.Done():
			log.Fatalf("scan timed out: %v", ctx.Err())
		case out := <-stdout:
			fmt.Printf("nmap output: %s\n", out)
		case errOut := <-stderr:
			fmt.Printf("nmap error output: %s\n", errOut)
		case result := <-resultCh:
			if result.Err != nil {
				log.Fatalf("running network scan: %v", result.Err)
			}

			fmt.Printf("Nmap done: %d hosts up\n", len(result.Result.Hosts))
			return
		}
	}
}
