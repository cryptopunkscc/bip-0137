package verify_test

import (
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/cryptopunkscc/bip-0137/verify"
)

// ExampleVerifyBip137Signature demonstrates how to verify a Bitcoin signature
// using a Bitcoin address.
func ExampleVerifyBip137Signature() {
	// Example with a real signature
	address := "194vDb9xwY6XQi5bLa7FRPBewJdUqympZ9"
	message := "Hello, Bitcoin testing!"
	signature := "IOeVH/0KqgmS3XKwqCJiwlcHonwxKMQN6fbOW5UsXSDZB4EGCVTXx6c+ZU/Ae5qO94MSBZn2aPOiUsupRIwBaAU="

	valid, err := verify.VerifyBip137Signature(address, message, signature)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Signature valid: %v\n", valid)
	// Output: Signature valid: true
}

// ExampleVerifyBip137SignatureWithPubKey demonstrates how to verify a Bitcoin signature
// using a public key directly.
func ExampleVerifyBip137SignatureWithPubKey() {
	// Public key in hex format
	pubKeyHex := "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	message := "Hello, Bitcoin testing!"
	signature := "IOeVH/0KqgmS3XKwqCJiwlcHonwxKMQN6fbOW5UsXSDZB4EGCVTXx6c+ZU/Ae5qO94MSBZn2aPOiUsupRIwBaAU="

	// This is a simplified example - normally you'd get the pubKey from an address
	// or from elsewhere, and would include proper error handling
	pubKeyBytes, _ := hex.DecodeString(pubKeyHex)
	pubKey, _ := btcec.ParsePubKey(pubKeyBytes)

	valid, err := verify.VerifyWithPubKey(pubKey, message, signature)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Signature valid: %v\n", valid)
	// Output: Signature valid: true
}
