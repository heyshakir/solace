package main

import (
	"fmt"
	"log"

	"solace/internal/engine"
	"solace/internal/osops"
)

func main() {
	fmt.Println("Starting Solace (v0.1.0-alpha)")
	fmt.Println("--------------------------------------------------")

	// OS 
	osEngine, err := osops.NewEngine()
	if err != nil {
		log.Fatalf("✖ Critical Error: %v\n", err)
	}
	fmt.Printf("✔ operating system detection: %s\n", osEngine.GetOSName())

	// hardening 
	hEngine := engine.NewHardeningEngine()
	mockRules := hEngine.LoadMockRules() // to be updated.

	fmt.Printf("✔ hardening engine initialized.\n")
	fmt.Printf("✔ Loaded %d mock rules successfully.\n", len(mockRules))
	
	fmt.Println("--------------------------------------------------")
}
