package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"strings"

	"github.com/Ullaakut/nmap/v2"
)

// CustomType is your custom type in code.
// You just have to make it a Streamer.
type CustomType struct {
	nmap.Streamer
	File string
}

// Write is a function that handles the normal nmap stdout
func (c *CustomType) Write(d []byte) (int, error) {
	var err error
	lines := string(d)

	if strings.Contains(lines, "Stats: ") {
		fmt.Print(lines)
	}
	return len(d), err
}

// Bytes returns scan result bytes
func (c *CustomType) Bytes() []byte {
	data, err := ioutil.ReadFile(c.File)
	if err != nil {
		data = append(data, "\ncould not read File"...)
	}
	return data
}

func main() {
	cType := &CustomType{
		File: "/tmp/output.xml",
	}
	scanner, err := nmap.NewScanner(
		nmap.WithTargets("localhost"),
		nmap.WithPorts("1-4000"),
		nmap.WithServiceInfo(),
		nmap.WithVerbosity(3),
	)
	if err != nil {
		log.Fatalf("unable to create nmap scanner: %v", err)
	}

	warnings, err := scanner.RunWithStreamer(cType, cType.File)
	if err != nil {
		log.Fatalf("unable to run nmap scan: %v", err)
	}

	fmt.Printf("Nmap warnings: %v\n", warnings)

	result, err := nmap.Parse(cType.Bytes())
	if err != nil {
		log.Fatalf("unable to parse nmap output: %v", err)
	}

	fmt.Printf("Nmap done: %d hosts up scanned in %.2f seconds\n", len(result.Hosts), result.Stats.Finished.Elapsed)
}
