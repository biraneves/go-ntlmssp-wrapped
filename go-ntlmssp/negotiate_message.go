package ntlmssp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"strings"
)

const expMsgBodyLen = 40

type negotiateMessageFields struct {
	messageHeader
	NegotiateFlags negotiateFlags

	Domain      varField
	Workstation varField

	Version
}

var defaultFlags = negotiateFlagNTLMSSPNEGOTIATETARGETINFO |
	negotiateFlagNTLMSSPNEGOTIATE56 |
	negotiateFlagNTLMSSPNEGOTIATE128 |
	negotiateFlagNTLMSSPNEGOTIATEUNICODE |
	negotiateFlagNTLMSSPNEGOTIATEEXTENDEDSESSIONSECURITY

// NewNegotiateMessage creates a new NEGOTIATE message with the
// flags that this package supports.
func NewNegotiateMessage(domainName, workstationName string) ([]byte, error) {
	payloadOffset := expMsgBodyLen
	flags := defaultFlags

	if domainName != "" {
		flags |= negotiateFlagNTLMSSPNEGOTIATEOEMDOMAINSUPPLIED
	}

	if workstationName != "" {
		flags |= negotiateFlagNTLMSSPNEGOTIATEOEMWORKSTATIONSUPPLIED
	}

	msg := negotiateMessageFields{
		messageHeader:  newMessageHeader(1),
		NegotiateFlags: flags,
		Domain:         newVarField(&payloadOffset, len(domainName)),
		Workstation:    newVarField(&payloadOffset, len(workstationName)),
		Version:        DefaultVersion(),
	}

	b := bytes.Buffer{}
	if err := binary.Write(&b, binary.LittleEndian, &msg); err != nil {
		log.Printf("[DEBUG]%s error writing message in buffer: %s", CallerInfo(), err.Error())
		return nil, err
	}
	if b.Len() != expMsgBodyLen {
		log.Printf("[DEBUG]%s incorrect body length", CallerInfo())
		return nil, errors.New("incorrect body length")
	}

	payload := strings.ToUpper(domainName + workstationName)
	if _, err := b.WriteString(payload); err != nil {
		log.Printf("[DEBUG]%s error writing payload: %s", CallerInfo(), err.Error())
		return nil, err
	}

	return b.Bytes(), nil
}
