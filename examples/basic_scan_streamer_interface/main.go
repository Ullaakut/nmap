package main

import (
	"bytes"
	"fmt"
	"github.com/Ullaakut/nmap/v2"
	"io"
	"log"
)

// CustomType is your custom type in code.
// You just have to make it a Streamer.
type CustomType struct {
	io.Writer
	buf bytes.Buffer
}

// Write is a function that handles the normal nmap stdout.
func (c *CustomType) Write(d []byte) (int, error) {
	lines := string(d)
	fmt.Print(lines)
	return c.buf.Write(d)
}

// Bytes returns scan result bytes.
func (c *CustomType) Bytes() []byte {
	return c.buf.Bytes()
}

func main() {
	cType := &CustomType{}
	scanner, err := nmap.NewScanner(
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
	err = scanner.Streamer(cType).Run(&result, &warnings)
	if err != nil {
		log.Fatalf("unable to run nmap scan: %v", err)
	}

	fmt.Printf("Nmap warnings: %v\n", warnings)

	var result2 nmap.Run
	err = nmap.Parse(cType.Bytes(), &result2)
	if err != nil {
		log.Fatalf("unable to parse nmap output: %v", err)
	}

	fmt.Printf("Nmap done: %d hosts up scanned in %.2f seconds\n", len(result.Hosts), result.Stats.Finished.Elapsed)
	fmt.Printf("Streamer done: %d hosts up scanned in %.2f seconds\n", len(result2.Hosts), result.Stats.Finished.Elapsed)
}
