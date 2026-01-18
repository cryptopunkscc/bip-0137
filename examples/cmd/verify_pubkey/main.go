// Package main demonstrates how to verify Bitcoin signatures using a public key.
package main

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/cryptopunkscc/bip-0137/verify"
)

func main() {
	// Set log level to debug for detailed information
	verify.SetLogLevel(verify.LogLevelDebug)

	// Configure logging to stdout
	verify.Logger.SetOutput(os.Stdout)

	// Use the values from our key generation script
	address := "1C9YVXK12TBeDMJEFFMuTZMHMQgcRAuR1E"
	message := "Hello, Bitcoin testing!"
	signature := "IJNFSGvr6aaXsWFHQNJmWL9Jq6t/4IRdIzst8X4Af90JY7C0rStfn1NLgnQt8xWGSxouz5y/G7KWL8dKmt+FpME="
	pubKeyHex := "036cb4bc04b262a3a5b5815b4524ce058ecfb6148a26555fbc0eb1b722093c01d1"

	// Parse the public key from hex
	pubKeyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		fmt.Printf("Error decoding public key: %v\n", err)
		return
	}

	// Parse the public key from bytes
	pubKey, err := btcec.ParsePubKey(pubKeyBytes)
	if err != nil {
		fmt.Printf("Error parsing public key: %v\n", err)
		return
	}

	fmt.Println("============ VERIFYING NEWLY GENERATED BITCOIN SIGNATURE ============")
	fmt.Printf("Address:          %s\n", address)
	fmt.Printf("Public Key (hex): %s\n", pubKeyHex)
	fmt.Printf("Message:          %s\n", message)
	fmt.Printf("Signature:        %s\n", signature)
	fmt.Println("====================================================================")

	// First verify using public key directly (would still fail for now as implementation is a placeholder)
	fmt.Println("\n1. ATTEMPTING VERIFICATION WITH PUBLIC KEY:")
	valid, err := verify.VerifyBip137SignatureWithPubKey(pubKey, message, signature)
	if err != nil {
		fmt.Printf("  Verification ERROR: %v\n", err)
	} else {
		fmt.Printf("  Verification RESULT: %v\n", valid)
	}

	// Verify using the address-based method which should work
	fmt.Println("\n2. VERIFICATION WITH ADDRESS:")
	validWithAddress, err := verify.VerifyBip137Signature(address, message, signature)
	if err != nil {
		fmt.Printf("  Verification ERROR: %v\n", err)
	} else {
		fmt.Printf("  Verification RESULT: %v\n", validWithAddress)
	}
}
