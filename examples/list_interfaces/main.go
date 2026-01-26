package main

import (
	"context"
	"encoding/json"
	"log"

	"github.com/Ullaakut/nmap/v4"
)

func main() {
	ctx := context.Background()

	scanner, err := nmap.NewScanner()
	if err != nil {
		log.Fatalf("creating nmap scanner: %v", err)
	}

	interfaceList, err := scanner.InterfaceList(ctx)
	if err != nil {
		log.Fatalf("getting interface list: %v", err)
	}

	bytes, err := json.MarshalIndent(interfaceList, "", "\t")
	if err != nil {
		log.Fatalf("marshalling interface list: %v", err)
	}

	log.Println(string(bytes))
}
