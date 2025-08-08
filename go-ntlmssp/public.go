package ntlmssp

// GenerateType1 returns a raw NTLM Type 1 (Negotiate) message.
// It wraps NewNegotiateMessage and expose it for external use.
func GenerateType1(domain, workstation string) ([]byte, error) {
	return NewNegotiateMessage(domain, workstation)
}

// GenerateType3 returns a raw NTLM Type 3 (Authenticate) message,
// give a Type 2 NTLM challenge, user credentials, and domainNeeded flag.
// This wraps the internal ProcessChallenge function.
func GenerateType3(challenge []byte, username, password string, domainNeeded bool) ([]byte, error) {
	return ProcessChallenge(challenge, username, password, domainNeeded)
}
