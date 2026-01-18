// Package main demonstrates how to verify Bitcoin signatures using a public key.
package main

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/cryptopunkscc/bip-0137/verify"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

func main() {
	// Set log level to debug for detailed information
	verify.SetLogLevel(verify.LogLevelDebug)

	// Configure logging to stdout
	verify.Logger.SetOutput(os.Stdout)

	// Use the values from our key generation script
	message := "hello world"
	signature := "HyQbaQI5zcOPtCQJz03h6JetvFpnpnXcDjOTlnDId73nMDmLqCFPc5N80nYCTHT7lKoA8DHAwqSoJrT5qfGHjDk="
	pubKeyHex := "02713d43493912a98f8594d1aa7b6de501b075081e6f0b818a03fdd2737a42d8fd"

	// Parse the public key from hex
	pubKeyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		fmt.Printf("Error decoding public key: %v\n", err)
		return
	}

	// Parse the public key from bytes
	pubKey, err := secp256k1.ParsePubKey(pubKeyBytes)
	if err != nil {
		fmt.Printf("Error parsing public key: %v\n", err)
		return
	}

	fmt.Println("============ VERIFYING NEWLY GENERATED BITCOIN SIGNATURE ============")
	fmt.Printf("Public Key (hex): %s\n", pubKeyHex)
	fmt.Printf("Message:          %s\n", message)
	fmt.Printf("Signature:        %s\n", signature)
	fmt.Println("====================================================================")

	// First verify using public key directly (would still fail for now as implementation is a placeholder)
	valid, err := verify.VerifyWithPubKey(pubKey, message, signature)
	if err != nil {
		fmt.Printf("  Verification ERROR: %v\n", err)
	} else {
		fmt.Printf("  Verification RESULT: %v\n", valid)
	}

}
