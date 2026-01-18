// Package main demonstrates verifying Bitcoin signatures using an address.
package main

import (
	"fmt"
	"os"

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

	fmt.Println("================ VERIFYING BITCOIN SIGNATURE ================")
	fmt.Printf("Address:   %s\n", address)
	fmt.Printf("Message:   %s\n", message)
	fmt.Printf("Signature: %s\n", signature)
	fmt.Println("===========================================================")

	valid, err := verify.VerifyBip137Signature(address, message, signature)
	if err != nil {
		fmt.Printf("\nVerification ERROR: %v\n", err)
		return
	}

	fmt.Printf("\nVerification RESULT: %v\n", valid)
}
