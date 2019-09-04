package main

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/ullaakut/nmap"
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
		nmap.WithPorts("80,443,843"),
	)
	if err != nil {
		log.Fatalf("unable to create nmap scanner: %v", err)
	}

	// Executes asynchronously, allowing results to be streamed in real time.
	if err := s.RunAsync(); err != nil {
		panic(err)
	}

	// Goroutine to watch for stdout and print to screen. Additionally it stores
	// the bytes intoa variable for processiing later.
	go func() {
		for s.Stdout.Scan() {
			fmt.Println(s.Stdout.Text())
			resultBytes = append(resultBytes, s.Stdout.Bytes()...)
		}
	}()

	// Goroutine to watch for stderr and print to screen. Additionally it stores
	// the bytes intoa variable for processiing later.
	go func() {
		for s.Stderr.Scan() {
			errorBytes = append(errorBytes, s.Stderr.Bytes()...)
		}
	}()

	// Blocks main until the scan has completed.
	if err := s.Cmd.Wait(); err != nil {
		panic(err)
	}

	// Parsing the results into corresponding structs
	results, err := nmap.Parse(resultBytes)

	// Parsing the results into the NmapError slice of our nmap Struct
	results.NmapErrors = strings.Split(string(errorBytes), "\n")
	if err != nil {
		panic(err)
	}

	jsonResults, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		panic(err)
	}

	fmt.Printf("%s\n", jsonResults)
}
