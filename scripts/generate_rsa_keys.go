package main

import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/x509"
    "encoding/pem"
    "fmt"
    "os"
    "path/filepath"
)

func GenerateRsaKeys() {
    // Generate a 2048-bit RSA private key
    privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        panic(err)
    }

    // Ensure the certs/ directory exists
    certsDir := "certs"
    err = os.MkdirAll(certsDir, 0700)
    if err != nil {
        panic(err)
    }

    // Write private key
    privPath := filepath.Join(certsDir, "private.pem")
    privFile, err := os.Create(privPath)
    if err != nil {
        panic(err)
    }
    defer privFile.Close()

    privBytes := x509.MarshalPKCS1PrivateKey(privateKey)
    pem.Encode(privFile, &pem.Block{
        Type:  "RSA PRIVATE KEY",
        Bytes: privBytes,
    })
    fmt.Println("Private key saved to", privPath)

    // Write public key
    pubPath := filepath.Join(certsDir, "public.pem")
    pubFile, err := os.Create(pubPath)
    if err != nil {
        panic(err)
    }
    defer pubFile.Close()

    pubASN1, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
    if err != nil {
        panic(err)
    }

    pem.Encode(pubFile, &pem.Block{
        Type:  "PUBLIC KEY",
        Bytes: pubASN1,
    })
    fmt.Println("Public key saved to", pubPath)
}

