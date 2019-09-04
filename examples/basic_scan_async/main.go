package main

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/Ullaakut/nmap"
)

func main() {
	var (
		resultBytes []byte
		errorBytes []byte
	)
	var errorBytes []byte
	s, err := nmap.NewScanner(
		nmap.WithTargets("google.com", "facebook.com", "youtube.co1m"),
		nmap.WithPorts("80,443,843"),
	)
	if err != nil {
		log.Fatalf("unable to create nmap scanner: %v", err)
	}

	if err := s.RunAsync(); err != nil {
		panic(err)
	}

	go func() {
		for s.Stdout.Scan() {
			fmt.Println(s.Stdout.Text())
			resultBytes = append(resultBytes, s.Stdout.Bytes()...)
		}
	}()

	go func() {
		for s.Stderr.Scan() {
			errorBytes = append(errorBytes, s.Stderr.Bytes()...)
		}
	}()

	if err := s.Cmd.Wait(); err != nil {
		panic(err)
	}

	results, err := nmap.Parse(resultBytes)
	results.NmapErrors = strings.Split(string(errorBytes), "\n")
	if err != nil {
		panic(err)
	}

	temp, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s\n", temp)
}
