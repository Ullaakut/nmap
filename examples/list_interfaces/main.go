package main

import (
	"encoding/json"
	"fmt"
	"github.com/Ullaakut/nmap/v2"
	"log"
)

func main() {
	scanner, err := nmap.NewScanner()
	if err != nil {
		log.Fatalf("unable to create nmap scanner: %v", err)
	}

	interfaceList, err := scanner.GetInterfaceList()

	bytes, err := json.MarshalIndent(interfaceList, "", "   ")
	if err != nil {
		log.Fatalf("unable to marshall: %v", err)
	}

	fmt.Println(string(bytes))
}
