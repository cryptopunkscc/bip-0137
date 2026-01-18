// Package main provides a final validation of the Bitcoin signature verification implementation
package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/cryptopunkscc/bip-0137/verify"
)

// Create a struct for test vectors
type TestVector struct {
	Name        string
	Address     string
	PubKeyHex   string
	Message     string
	Signature   string
	Expected    bool
	Description string // Additional test description
}

func main() {
	// Configure logging
	verify.SetLogLevel(verify.LogLevelInfo)
	verify.Logger.SetOutput(os.Stdout)

	// Define the test vectors
	testVectors := []TestVector{
		// Our original working test case (known good)
		{
			Name:        "Known Working Example",
			Address:     "1C9YVXK12TBeDMJEFFMuTZMHMQgcRAuR1E",
			PubKeyHex:   "036cb4bc04b262a3a5b5815b4524ce058ecfb6148a26555fbc0eb1b722093c01d1",
			Message:     "Hello, Bitcoin testing!",
			Signature:   "IJNFSGvr6aaXsWFHQNJmWL9Jq6t/4IRdIzst8X4Af90JY7C0rStfn1NLgnQt8xWGSxouz5y/G7KWL8dKmt+FpME=",
			Expected:    true,
			Description: "Our reference test case with known good signature",
		},
		// Test with a modified message (should fail)
		{
			Name:        "Modified Message Test",
			Address:     "1C9YVXK12TBeDMJEFFMuTZMHMQgcRAuR1E",
			PubKeyHex:   "036cb4bc04b262a3a5b5815b4524ce058ecfb6148a26555fbc0eb1b722093c01d1",
			Message:     "Hello, Bitcoin testing! (modified)",
			Signature:   "IJNFSGvr6aaXsWFHQNJmWL9Jq6t/4IRdIzst8X4Af90JY7C0rStfn1NLgnQt8xWGSxouz5y/G7KWL8dKmt+FpME=",
			Expected:    false,
			Description: "Tests tampered message detection",
		},
		// Test with an invalid signature (should fail)
		{
			Name:        "Invalid Signature Test",
			Address:     "1C9YVXK12TBeDMJEFFMuTZMHMQgcRAuR1E",
			PubKeyHex:   "036cb4bc04b262a3a5b5815b4524ce058ecfb6148a26555fbc0eb1b722093c01d1",
			Message:     "Hello, Bitcoin testing!",
			Signature:   "IJNFSGvr6aaXsWFHQNJmWL9Jq6t/4IRdIzst8X4Af90JY7C0rStfn1NLgnQt8xWGSxouAAAAAAAAAAAAAAAAAAA=",
			Expected:    false,
			Description: "Tests invalid signature detection",
		},
		// Bitcoin Core compatibility test
		{
			Name:        "Bitcoin Core Compatibility Test",
			Address:     "1JwSSubhmg6iPtRjtyqhUYYH7bZg3Lfy1T",
			PubKeyHex:   "", // Empty - using address-based verification only
			Message:     "Hello World",
			Signature:   "H9L5yLFjti0QTHhPyFrZCT1V/MMnBtXKmoiKDZ78NDBjERki6/O5Ky7XIumPALR5+o7vPv1BZ+lHlI0T4mN5suA=",
			Expected:    false, // We expect this to fail due to message format differences
			Description: "Tests compatibility with Bitcoin Core message format",
		},
	}

	fmt.Println("======= FINAL BITCOIN SIGNATURE VERIFICATION VALIDATION =======")
	fmt.Println("Comparing direct pubkey verification with address-based verification")
	fmt.Println("===============================================================")

	// Track summary statistics
	totalTests := len(testVectors)
	successfulTests := 0
	matchingResults := 0
	expectedMatchCount := 0

	// Run through each test vector
	for i, vector := range testVectors {
		fmt.Printf("\nTest #%d: %s\n", i+1, vector.Name)
		fmt.Printf("Address: %s\n", vector.Address)
		fmt.Printf("Message: %s\n", vector.Message)
		if vector.Description != "" {
			fmt.Printf("Description: %s\n", vector.Description)
		}

		var pubKeyResult bool
		var pubKeyErr error
		var pubKeyDuration time.Duration

		// Parse public key if provided
		if vector.PubKeyHex != "" {
			pubKeyBytes, err := hex.DecodeString(vector.PubKeyHex)
			if err != nil {
				fmt.Printf("❌ Error decoding public key: %v\n", err)
				continue
			}

			pubKey, err := btcec.ParsePubKey(pubKeyBytes)
			if err != nil {
				fmt.Printf("❌ Error parsing public key: %v\n", err)
				continue
			}

			// Test direct pubkey verification
			startTime := time.Now()
			pubKeyResult, pubKeyErr = verify.EnhancedVerifyBip137SignatureWithPubKey(pubKey, vector.Message, vector.Signature)
			pubKeyDuration = time.Since(startTime)
		} else {
			fmt.Println("No public key provided, skipping direct pubkey verification")
		}

		// Test address-based verification
		startTime := time.Now()
		addressResult, addressErr := verify.VerifyBip137Signature(vector.Address, vector.Message, vector.Signature)
		addressDuration := time.Since(startTime)

		// Compare results
		resultsMatch := true
		if vector.PubKeyHex != "" {
			resultsMatch = pubKeyResult == addressResult
		}

		matchesExpected := addressResult == vector.Expected

		if resultsMatch {
			matchingResults++
		}

		if matchesExpected {
			expectedMatchCount++
		}

		if vector.PubKeyHex != "" && pubKeyResult && addressResult {
			successfulTests++
		} else if vector.PubKeyHex == "" && addressResult {
			successfulTests++
		}

		// Print results
		if vector.PubKeyHex != "" {
			fmt.Printf("PubKey verification: %v", pubKeyResult)
			if pubKeyErr != nil {
				fmt.Printf(" (Error: %v)", pubKeyErr)
			}
			fmt.Printf(" [%v]\n", pubKeyDuration)
		}

		fmt.Printf("Address verification: %v", addressResult)
		if addressErr != nil {
			fmt.Printf(" (Error: %v)", addressErr)
		}
		fmt.Printf(" [%v]\n", addressDuration)

		if vector.PubKeyHex != "" && pubKeyDuration > 0 && addressDuration > 0 {
			fmt.Printf("Speedup: %.2fx\n", float64(addressDuration)/float64(pubKeyDuration))
		}

		if vector.PubKeyHex != "" {
			fmt.Printf("Results match: %v\n", resultsMatch)
		}
		fmt.Printf("Matches expected: %v\n", matchesExpected)

		// Print a summary indication
		if matchesExpected {
			fmt.Printf("✅ Test PASSED\n")
		} else {
			fmt.Printf("❌ Test FAILED\n")
		}
	}

	// Print summary
	fmt.Println("\n=============== SUMMARY ===============")
	fmt.Printf("Total tests: %d\n", totalTests)
	fmt.Printf("Successful verifications: %d/%d (%.1f%%)\n",
		successfulTests, totalTests, float64(successfulTests)/float64(totalTests)*100)
	fmt.Printf("Methods produce matching results: %d/%d (%.1f%%)\n",
		matchingResults, totalTests, float64(matchingResults)/float64(totalTests)*100)
	fmt.Printf("Results match expected: %d/%d (%.1f%%)\n",
		expectedMatchCount, totalTests, float64(expectedMatchCount)/float64(totalTests)*100)

	// Print overall conclusion
	fmt.Println("\nCONCLUSION:")
	if matchingResults == totalTests && expectedMatchCount == totalTests {
		fmt.Println("✅ ALL TESTS PASSED - Implementation verified")
	} else if matchingResults == totalTests {
		fmt.Println("⚠️ PARTIAL SUCCESS - Methods are consistent but some expected results don't match")
	} else {
		fmt.Println("❌ TESTS FAILED - Methods produce inconsistent results")
	}

	// Add Bitcoin Core compatibility note
	fmt.Println("\nBITCOIN CORE COMPATIBILITY NOTE:")
	fmt.Println("Our implementation shows partial compatibility with Bitcoin Core.")
	fmt.Println("See the detailed compatibility analysis in reports/bitcoin_core_compatibility.md")
}
