package verify

import (
	"context"
	"errors"
	"fmt"
	"time"

	verifier "github.com/bitonicnl/verify-signed-message/pkg"
	"github.com/btcsuite/btcd/chaincfg"
)

// Common errors that can occur during signature verification
var (
	ErrVerificationTimeout = errors.New("signature verification timed out")
	ErrInvalidSignature    = errors.New("invalid signature")
	ErrEmptyAddress        = errors.New("empty bitcoin address")
	ErrEmptyMessage        = errors.New("empty message")
	ErrEmptySignature      = errors.New("empty signature")
)

// SignedMessage represents a message that has been signed with a Bitcoin private key
type SignedMessage struct {
	// Address is the Bitcoin address that allegedly signed the message
	Address string

	// Message is the content that was signed
	Message string

	// Signature is the base64-encoded signature
	Signature string
}

// VerifyBip137Signature verifies if a message was signed by the private key
// associated with the provided Bitcoin address according to BIP-0137.
// It uses the Bitcoin mainnet parameters by default.
func VerifyBip137Signature(address, message, signatureBase64 string) (bool, error) {
	return VerifyBip137SignatureWithParams(address, message, signatureBase64, &chaincfg.MainNetParams)
}

// VerifyBip137SignatureWithParams verifies a BIP-0137 signature using the provided
// network parameters (mainnet, testnet, etc.).
func VerifyBip137SignatureWithParams(address, message, signatureBase64 string, params *chaincfg.Params) (bool, error) {
	// Validate inputs
	if address == "" {
		return false, ErrEmptyAddress
	}
	if message == "" {
		return false, ErrEmptyMessage
	}
	if signatureBase64 == "" {
		return false, ErrEmptySignature
	}

	// Create a signed message struct
	signedMessage := verifier.SignedMessage{
		Address:   address,
		Message:   message,
		Signature: signatureBase64,
	}

	// Verify the signature using the provided network parameters
	valid, err := verifier.VerifyWithChain(signedMessage, params)
	if err != nil {
		return false, fmt.Errorf("signature verification error: %w", err)
	}

	return valid, nil
}

// VerifyBip137SignatureWithContext verifies a BIP-0137 signature with context support
// for timeout and cancellation. This is the recommended approach for 2025.
func VerifyBip137SignatureWithContext(ctx context.Context, msg SignedMessage) (bool, error) {
	LogInfo("Starting context-based signature verification")

	// Check if context has a deadline
	if deadline, ok := ctx.Deadline(); ok {
		LogDebug("Context has deadline: %s (timeout in %s)",
			deadline.Format(time.RFC3339), time.Until(deadline))
	} else {
		LogDebug("Context has no deadline")
	}

	// Create a channel to receive the verification result
	resultCh := make(chan struct {
		valid bool
		err   error
	}, 1)

	// Run verification in a goroutine
	startTime := time.Now()
	go func() {
		LogDebug("Starting verification goroutine")
		// Create a signed message struct
		signedMessage := verifier.SignedMessage{
			Address:   msg.Address,
			Message:   msg.Message,
			Signature: msg.Signature,
		}

		// Verify the signature
		valid, err := verifier.Verify(signedMessage)
		duration := time.Since(startTime)
		LogDebug("Verification completed in goroutine after %s", duration)

		resultCh <- struct {
			valid bool
			err   error
		}{valid, err}
	}()

	// Wait for either the context to be done or the verification to complete
	select {
	case <-ctx.Done():
		ctxErr := ctx.Err()
		LogError("Context cancelled or timed out: %v", ctxErr)
		return false, fmt.Errorf("%w: %v", ErrVerificationTimeout, ctxErr)
	case result := <-resultCh:
		if result.err != nil {
			LogError("Signature verification error: %v", result.err)
			return false, fmt.Errorf("signature verification error: %w", result.err)
		}
		LogInfo("Context-based verification result: %t", result.valid)
		return result.valid, nil
	}
}

// LogWarning logs a warning message
func LogWarning(format string, args ...interface{}) {
	if currentLogLevel >= LogLevelInfo {
		Logger.Printf("[WARNING] "+format, args...)
	}
}
