package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/Ullaakut/nmap/v3"
	"log"
)

func main() {
	scanner, err := nmap.NewScanner(context.Background())
	if err != nil {
		log.Fatalf("unable to create nmap scanner: %v", err)
	}

	interfaceList, err := scanner.GetInterfaceList()
	if err != nil {
		log.Fatalf("could not get interface list: %v", err)
	}

	bytes, err := json.MarshalIndent(interfaceList, "", "\t")
	if err != nil {
		log.Fatalf("unable to marshal: %v", err)
	}

	fmt.Println(string(bytes))
}
