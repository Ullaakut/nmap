package main

import (
	"fmt"
	"log"
	"strings"

	"github.com/Ullaakut/nmap"
)

func main() {
	var (
		resultBytes []byte
		errorBytes  []byte
	)
	// Equivalent to `/usr/local/bin/nmap -p 80,443,843 google.com facebook.com youtube.com`,
	// with a 5 minute timeout.
	s, err := nmap.NewScanner(
		nmap.WithTargets("google.com", "facebook.com", "youtube.com"),
		nmap.WithPorts("80,443,843,1-100"),
		nmap.WithStatsEvery("1s"),
	)
	if err != nil {
		log.Fatalf("unable to create nmap scanner: %v", err)
	}

	// Executes asynchronously, allowing results to be streamed in real time.
	nmapResults, nmapErrors, err := s.RunAsync()
	if err != nil {
		panic(err)
	}

	// Goroutine to watch for stdout and print to screen. Additionally it stores
	// the bytes into a variable for processing later.
	go func() {
		for result := range nmapResults {
			s.Progress(result)
			//fmt.Print(string(result))
			resultBytes = append(resultBytes, result...)
		}
	}()

	// Goroutine to watch for stderr and print to screen. Additionally it stores
	// the bytes intoa variable for processiing later.
	go func() {
		for err := range nmapErrors {
			errorBytes = append(errorBytes, err...)
		}
	}()

	// Blocks main until the scan has completed.
	if err := s.Wait(); err != nil {
		panic(err)
	}

	// Parsing the results into corresponding structs.
	result, err := nmap.Parse(resultBytes)

	// Parsing the results into the NmapError slice of our nmap Struct.
	result.NmapErrors = strings.Split(string(errorBytes), "\n")
	if err != nil {
		panic(err)
	}

	// Use the results to print an example output
	for _, host := range result.Hosts {
		if len(host.Ports) == 0 || len(host.Addresses) == 0 {
			continue
		}

		fmt.Printf("Host %q:\n", host.Addresses[0])

		for _, port := range host.Ports {
			fmt.Printf("\tPort %d/%s %s %s\n", port.ID, port.Protocol, port.State, port.Service.Name)
		}
	}
}
