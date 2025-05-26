package main

import (
	"encoding/json"
	"log"
	"os"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

func HostPublicKeysLocally() {
	if _, err := os.Stat("public"); os.IsNotExist(err) {
		err = os.Mkdir("public", 0755)
		if err != nil {
			log.Fatalf("Failed to create public directory: %v", err)
		}
	}

	if _, err := os.Stat("public/.well-known"); os.IsNotExist(err) {
		err = os.Mkdir("public/.well-known", 0755)
		if err != nil {
			log.Fatalf("Failed to create .well-known directory: %v", err)
		}
	}

	_, err := os.Stat("public/.well-known/jwks.json")
	if os.IsNotExist(err) {
		err = os.WriteFile("public/.well-known/jwks.json", []byte("{}"), 0644)
		if err != nil {
			log.Fatalf("Failed to create jwks.json: %v", err)
		}
	}
	set, err := jwk.ReadFile("certs/private.pem", jwk.WithPEM(true))
	key, ok := set.Key(0)
	if !ok {
		log.Fatal("Key does not exists on the requested index")
	}
	jwksPath := "public/.well-known/jwks.json"
	pubkey, err := key.PublicKey()
	if err != nil {
		log.Fatalf("Failed to get public key: %v", err)
	}
    // setting this field manually for third party convinience
    pubkey.Set("use","sig")

	pubSet := jwk.NewSet()
	pubSet.AddKey(pubkey)

	// Marshal the JWKS set to JSON
	jsonBytes, err := json.MarshalIndent(pubSet, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal JWKS: %v", err)
	}

	// Write the JSON to the file
	err = os.WriteFile(jwksPath, jsonBytes, 0644)
	if err != nil {
		log.Fatalf("Failed to write JWKS to file: %v", err)
	}

	log.Println("Successfully wrote JWKS to", jwksPath)
}
