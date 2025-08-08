package ntlmssp

import (
	"bytes"
	"encoding/binary"
	"errors"
)

// GenerateType1 returns a raw NTLM Type 1 (Negotiate) message.
// It wraps NewNegotiateMessage and expose it for external use.
func GenerateType1(domain, workstation string) ([]byte, error) {
	return NewNegotiateMessage(domain, workstation)
}

// GenerateType3 creates an NTLM Type 3 message based on the server challenge and user.
// It implements NTLMv2 Authenticate message generation.
func GenerateType3(challenge []byte, username, password, domain string, domainNeeded bool) ([]byte, error) {
	// Sanity checks
	if len(challenge) < 48 {
		return nil, errors.New("invalid challenge: too short")
	}

	// Parse header
	var header messageHeader
	if err := binary.Read(bytes.NewReader(challenge[:8]), binary.LittleEndian, &header); err != nil {
		return nil, err
	}
	if !header.IsValid() || header.MessageType != 2 {
		return nil, errors.New("not a valid NTLM Type 2 message")
	}

	// Extract server challenge
	serverChallenge := challenge[24:32]

	// Extract target info (AV Pairs), if any
	targetInfoOffset := binary.LittleEndian.Uint32(challenge[40:44])
	targetInfoLen := binary.LittleEndian.Uint16(challenge[36:38])

	var targetInfo []byte
	if targetInfoOffset > 0 && targetInfoLen > 0 && int(targetInfoOffset)+int(targetInfoLen) <= len(challenge) {
		targetInfo = challenge[targetInfoOffset : targetInfoOffset+uint32(targetInfoLen)]
	} else {
		targetInfo = []byte{}
	}

	// Split domain if needed
	user := username
	if domainNeeded {
		if domain == "" {
			return nil, errors.New("domain is required for ntlmv2 when domainNeeded is true")
		}
	} else {
		domain = ""
	}

	// Create NTLMv2 hash and client challenge
	ntlmV2Hash := getNtlmV2Hash(password, user, domain)
	clientChallenge, err := generateClientChallenge()
	if err != nil {
		return nil, err
	}

	timestamp := generateTimestamp()

	// Responses
	ntResp := computeNtlmV2Response(ntlmV2Hash, serverChallenge, clientChallenge, timestamp, targetInfo)
	lmResp := computeLmV2Response(ntlmV2Hash, serverChallenge, clientChallenge)

	// Build final message
	type3, err := NewAuthenticateMessage(
		domain,
		user,
		"", // workstation
		ntResp,
		lmResp,
		targetInfo,
		timestamp,
		clientChallenge,
	)
	if err != nil {
		return nil, err
	}

	return type3, nil
}
