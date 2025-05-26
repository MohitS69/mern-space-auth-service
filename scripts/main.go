package main

import (
	"flag"
	"log"
)

func main() {
	arg := flag.String("arg", "", "Name of the script to run.")
    flag.Parse()
	val := *arg
	switch val {
	case "generate-rsa-keys":
		GenerateRsaKeys()
	case "host-pubkey-locally":
		HostPublicKeysLocally()
	default:
		log.Fatalf("Script %s does not exist", val)
	}
}
