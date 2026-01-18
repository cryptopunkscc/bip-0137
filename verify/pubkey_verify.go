package verify

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
)

func VerifyWithPubKey(pubKey *secp256k1.PublicKey, message, signatureBase64 string) (bool, error) {
	// First attempt: Direct verification with public key
	valid, err := verifySignatureDirectly(pubKey, message, signatureBase64)
	if err == nil {
		return valid, nil
	}

	// Second attempt: Derive address and use address-based verification
	return verifyWithDerivedAddress(pubKey, message, signatureBase64)
}

// verifySignatureDirectly attempts to verify a Bitcoin message signature directly
// using the provided public key.
func verifySignatureDirectly(pubKey *btcec.PublicKey, message, signatureBase64 string) (bool, error) {
	// Decode signature from base64
	sigBytes, err := base64.StdEncoding.DecodeString(signatureBase64)
	if err != nil {
		return false, fmt.Errorf("invalid base64 signature: %w", err)
	}

	if len(sigBytes) < 65 {
		return false, fmt.Errorf("signature too short (expected at least 65 bytes)")
	}

	// Extract recovery ID and signature components
	headerByte := sigBytes[0]
	LogDebug("Signature header byte: 0x%02x", headerByte)

	// Verify header byte is valid per BIP-137
	recoveryID := int(headerByte-27) % 4
	isCompressed := headerByte >= 31 // 31-34 = compressed, 27-30 = uncompressed

	// Check that the header byte is within valid ranges for a standard Bitcoin signature
	if (headerByte < 27 || headerByte > 34) &&
		(headerByte < 35 || headerByte > 42) {
		LogError("Invalid header byte: 0x%02x", headerByte)
		return false, fmt.Errorf("invalid signature header byte: 0x%02x", headerByte)
	}

	LogDebug("Recovery ID: %d, Compressed: %t", recoveryID, isCompressed)

	// Format the message according to Bitcoin signed message format and hash it
	formattedMsg := formatBitcoinMessageForVerification(message)

	// Double SHA-256 hash the formatted message
	messageHash := sha256.Sum256(formattedMsg)
	messageHash = sha256.Sum256(messageHash[:])

	// Extract the R and S components (bytes 1-33 and 33-65)
	rBytes := sigBytes[1:33]
	sBytes := sigBytes[33:65]

	LogDebug("Signature R component: %x", rBytes)
	LogDebug("Signature S component: %x", sBytes)

	// Create a DER signature from R and S components
	// Standard DER format:
	// 0x30 <length> 0x02 <length of R> <R> 0x02 <length of S> <S>
	rLen := len(rBytes)
	sLen := len(sBytes)

	// Remove any leading zeros from R and S
	for rLen > 0 && rBytes[0] == 0 {
		rBytes = rBytes[1:]
		rLen--
	}

	for sLen > 0 && sBytes[0] == 0 {
		sBytes = sBytes[1:]
		sLen--
	}

	// Ensure R and S are positive (add a leading zero if high bit is set)
	if rLen > 0 && rBytes[0]&0x80 != 0 {
		rBytes = append([]byte{0x00}, rBytes...)
		rLen++
	}

	if sLen > 0 && sBytes[0]&0x80 != 0 {
		sBytes = append([]byte{0x00}, sBytes...)
		sLen++
	}

	// Calculate total length
	totalLen := 2 + rLen + 2 + sLen // 0x30 <len> 0x02 <rlen> <r> 0x02 <slen> <s>

	// Create DER signature
	der := make([]byte, totalLen+2)
	der[0] = 0x30              // Sequence
	der[1] = byte(totalLen)    // Length
	der[2] = 0x02              // Integer
	der[3] = byte(rLen)        // Length of R
	copy(der[4:], rBytes)      // R value
	der[4+rLen] = 0x02         // Integer
	der[5+rLen] = byte(sLen)   // Length of S
	copy(der[6+rLen:], sBytes) // S value

	LogDebug("Created DER signature: %x", der)

	// Parse the DER signature
	signature, err := ecdsa.ParseDERSignature(der)
	if err != nil {
		LogError("Error parsing DER signature: %v", err)
		return false, fmt.Errorf("error parsing signature: %w", err)
	}

	// Verify the signature against the message hash and public key
	valid := signature.Verify(messageHash[:], pubKey)

	LogDebug("Direct verification result: %v", valid)
	return valid, nil
}

// verifyWithDerivedAddress derives a Bitcoin address from the public key and uses
// address-based verification as a fallback.
func verifyWithDerivedAddress(pubKey *btcec.PublicKey, message, signatureBase64 string) (bool, error) {
	// Determine if the signature uses a compressed or uncompressed key
	// from the signature header byte
	sigBytes, err := base64.StdEncoding.DecodeString(signatureBase64)
	if err != nil {
		return false, fmt.Errorf("invalid base64 signature: %w", err)
	}

	if len(sigBytes) < 1 {
		return false, fmt.Errorf("signature too short")
	}

	// Derive the address from the public key
	derivedAddress, err := deriveAddressFromPubKey(pubKey, &chaincfg.MainNetParams)
	if err != nil {
		return false, fmt.Errorf("failed to derive address from public key: %w", err)
	}

	return VerifyBip137Signature(derivedAddress, message, signatureBase64)
}

// deriveAddressFromPubKey derives a Bitcoin address from a public key
func deriveAddressFromPubKey(pubKey *btcec.PublicKey, params *chaincfg.Params) (string, error) {
	// Convert the public key to a btcutil.Address
	pubKeyHash := btcutil.Hash160(pubKey.SerializeCompressed())
	addr, err := btcutil.NewAddressPubKeyHash(pubKeyHash, params)
	if err != nil {
		return "", fmt.Errorf("error creating address from public key: %w", err)
	}

	// Return the address string
	return addr.EncodeAddress(), nil
}

// DeriveAddressFromPubKey derives a Bitcoin address from a public key using mainnet parameters.
// This is a utility function that can be used by external code.
func DeriveAddressFromPubKey(pubKey *btcec.PublicKey) (string, error) {
	return deriveAddressFromPubKey(pubKey, &chaincfg.MainNetParams)
}

// formatBitcoinMessageForVerification formats a message according to the Bitcoin
// signed message format: "Bitcoin Signed Message:\n" + message
func formatBitcoinMessageForVerification(message string) []byte {
	prefix := "Bitcoin Signed Message:\n"

	// Bitcoin's message format uses a compact size encoding for the lengths
	// Prefix: "Bitcoin Signed Message:\n"
	// Message: the actual message being signed

	// First, we create a temporary buffer to hold our formatted message
	var result []byte

	// Add the prefix with varint length
	prefixBytes := []byte(prefix)
	result = appendCompactSize(result, uint64(len(prefixBytes)))
	result = append(result, prefixBytes...)

	// Add the message with varint length
	messageBytes := []byte(message)
	result = appendCompactSize(result, uint64(len(messageBytes)))
	result = append(result, messageBytes...)

	LogTrace("Formatted Bitcoin message (hex): %x", result)
	return result
}

// appendCompactSize appends a compact size uint to a byte slice in Bitcoin's format
func appendCompactSize(b []byte, n uint64) []byte {
	if n < 253 {
		return append(b, byte(n))
	} else if n <= 0xffff {
		b = append(b, 253)
		return append(b, byte(n), byte(n>>8))
	} else if n <= 0xffffffff {
		b = append(b, 254)
		return append(b, byte(n), byte(n>>8), byte(n>>16), byte(n>>24))
	} else {
		b = append(b, 255)
		return append(b, byte(n), byte(n>>8), byte(n>>16), byte(n>>24),
			byte(n>>32), byte(n>>40), byte(n>>48), byte(n>>56))
	}
}
