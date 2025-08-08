package ntlmssp

import (
	"bytes"
	"encoding/binary"
)

// NewAuthenticateMessage constructs a NTLM Type 3 (Authenticate) message.
//
// Parameters:
//   - domain: NTLM domain name
//   - username: account username (without domain)
//   - workstation: machine name (optional, often empty)
//   - ntChallenge: full NTLMv2 response from computeNtlmV2Response()
//   - lmChallenge: full LMv2 response from computeLmV2Response()
//   - targetInfo: AV pairs from the NTLM challenge message
//   - timestamp: generated timestamp for the response
//   - clientChallenge: 8-byte random challenge used in response
func NewAuthenticateMessage(
	domain, username, workstation string,
	ntChallenge, lmChallenge, targetInfo, timestamp, clientChallenge []byte,
) ([]byte, error) {
	var (
		payloadOffset = 88 // Starting after fixed-length fields
		buf           = &bytes.Buffer{}
	)

	domainBytes := toUnicode(domain)
	usernameBytes := toUnicode(username)
	workstationBytes := toUnicode(workstation)
	sessionKey := []byte{} // Not used in NTLMv2

	// Create variable fields
	domainField := newVarField(&payloadOffset, len(domainBytes))
	userField := newVarField(&payloadOffset, len(usernameBytes))
	workstationField := newVarField(&payloadOffset, len(workstationBytes))
	lmField := newVarField(&payloadOffset, len(lmChallenge))
	ntField := newVarField(&payloadOffset, len(ntChallenge))
	sessKeyField := newVarField(&payloadOffset, len(sessionKey))

	// NTLMSSP Signature and Type 3
	if err := binary.Write(buf, binary.LittleEndian, messageHeader{
		Signature:   signature,
		MessageType: 3,
	}); err != nil {
		return nil, err
	}

	// Order matters: write LM, NT, Domain, Username, Workstation, Session Key
	fields := []varField{lmField, ntField, domainField, userField, workstationField, sessKeyField}
	for _, f := range fields {
		if err := binary.Write(buf, binary.LittleEndian, f); err != nil {
			return nil, err
		}
	}

	// Negotiate flags
	flags := defaultFlags | negotiateFlagNTLMSSPNEGOTIATEALWAYSSIGN | negotiateFlagNTLMSSPNEGOTIATEVERSION
	if err := binary.Write(buf, binary.LittleEndian, flags); err != nil {
		return nil, err
	}

	// Version info (8 bytes)
	if err := binary.Write(buf, binary.LittleEndian, DefaultVersion()); err != nil {
		return nil, err
	}

	// MIC (Message Integrity Check) not computed: writing 16 zero bytes as placeholder
	mic := make([]byte, 16)
	if _, err := buf.Write(mic); err != nil {
		return nil, err
	}

	// Payload (in the order the fields point to)
	payloads := [][]byte{
		lmChallenge, ntChallenge,
		domainBytes, usernameBytes, workstationBytes,
		sessionKey,
	}
	for _, p := range payloads {
		if _, err := buf.Write(p); err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}
