package main

import (
	"context"
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
		nmap.WithTimingTemplate(nmap.TimingAggressive),
		nmap.WithProgress(time.Second, handleProgress),
	)
	if err != nil {
		log.Fatalf("creating nmap scanner: %v", err)
	}

	_, err = scanner.Run(ctx)
	if err != nil {
		log.Fatalf("running network scan: %v", err)
	}
}

func handleProgress(p nmap.TaskProgress) {
	log.Printf("task %q: %.2f%% remaining %d", p.Task, p.Percent, p.Remaining)
}
