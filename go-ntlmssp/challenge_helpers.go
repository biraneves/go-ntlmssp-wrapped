package ntlmssp

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"time"
)

// generateClientChallenge generates an 8-byte cryptographically secure random nonce.
// This is used is the NTLMv2 response to ensure uniqueness and freshness.
func generateClientChallenge() ([]byte, error) {
	challenge := make([]byte, 8)
	_, err := rand.Read(challenge)
	if err != nil {
		return nil, fmt.Errorf("failed to generate client challenge: %w", err)
	}
	return challenge, nil
}

// generateTimestamp returns the current time in Windows FILETIME format.
// This is a 64-bit value representing the number of 100-nanosecond intervals since January 1, 1601 (UTC).
func generateTimestamp() []byte {
	// Unix epoch in NT time format offset (in 100ns intervals)
	const windowsToUnixEpochOffset = 116444736000000000

	// Current time in 100ns intervals
	now := time.Now().UTC().UnixNano()/100 + windowsToUnixEpochOffset

	timestamp := make([]byte, 8)
	binary.LittleEndian.PutUint64(timestamp, uint64(now))
	return timestamp
}
