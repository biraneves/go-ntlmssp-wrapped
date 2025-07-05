package ntlmssp

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"log"
	"strings"
	"time"
)

type authenicateMessage struct {
	LmChallengeResponse []byte
	NtChallengeResponse []byte

	TargetName string
	UserName   string

	// only set if negotiateFlag_NTLMSSP_NEGOTIATE_KEY_EXCH
	EncryptedRandomSessionKey []byte

	NegotiateFlags negotiateFlags

	MIC []byte
}

type authenticateMessageFields struct {
	messageHeader
	LmChallengeResponse varField
	NtChallengeResponse varField
	TargetName          varField
	UserName            varField
	Workstation         varField
	_                   [8]byte
	NegotiateFlags      negotiateFlags
}

func (m authenicateMessage) MarshalBinary() ([]byte, error) {
	if !m.NegotiateFlags.Has(negotiateFlagNTLMSSPNEGOTIATEUNICODE) {
		log.Printf("[DEBUG]%s only unicode is supported", CallerInfo())
		return nil, errors.New("only unicode is supported")
	}

	target, user := toUnicode(m.TargetName), toUnicode(m.UserName)
	workstation := toUnicode("")

	ptr := binary.Size(&authenticateMessageFields{})
	f := authenticateMessageFields{
		messageHeader:       newMessageHeader(3),
		NegotiateFlags:      m.NegotiateFlags,
		LmChallengeResponse: newVarField(&ptr, len(m.LmChallengeResponse)),
		NtChallengeResponse: newVarField(&ptr, len(m.NtChallengeResponse)),
		TargetName:          newVarField(&ptr, len(target)),
		UserName:            newVarField(&ptr, len(user)),
		Workstation:         newVarField(&ptr, len(workstation)),
	}

	f.NegotiateFlags.Unset(negotiateFlagNTLMSSPNEGOTIATEVERSION)

	b := bytes.Buffer{}
	if err := binary.Write(&b, binary.LittleEndian, &f); err != nil {
		log.Printf("[DEBUG]%s error writing f in buffer: %s", CallerInfo(), err.Error())
		return nil, err
	}
	if err := binary.Write(&b, binary.LittleEndian, &m.LmChallengeResponse); err != nil {
		log.Printf("[DEBUG]%s error writing lm challenge response in buffer: %s", CallerInfo(), err.Error())
		return nil, err
	}
	if err := binary.Write(&b, binary.LittleEndian, &m.NtChallengeResponse); err != nil {
		log.Printf("[DEBUG]%s error writing nt challenge response in buffer: %s", CallerInfo(), err.Error())
		return nil, err
	}
	if err := binary.Write(&b, binary.LittleEndian, &target); err != nil {
		log.Printf("[DEBUG]%s error writing target in buffer: %s", CallerInfo(), err.Error())
		return nil, err
	}
	if err := binary.Write(&b, binary.LittleEndian, &user); err != nil {
		log.Printf("[DEBUG]%s error writing user in buffer: %s", CallerInfo(), err.Error())
		return nil, err
	}
	if err := binary.Write(&b, binary.LittleEndian, &workstation); err != nil {
		log.Printf("[DEBUG]%s error writing workstation in buffer: %s", CallerInfo(), err.Error())
		return nil, err
	}

	return b.Bytes(), nil
}

// ProcessChallenge crafts an AUTHENTICATE message in response to the CHALLENGE message
// that was received from the server
func ProcessChallenge(challengeMessageData []byte, user, password string, domainNeeded bool) ([]byte, error) {
	if user == "" && password == "" {
		log.Printf("[DEBUG]%s anonymous authentication not supported", CallerInfo())
		return nil, errors.New("anonymous authentication not supported")
	}

	var cm challengeMessage
	if err := cm.UnmarshalBinary(challengeMessageData); err != nil {
		log.Printf("[DEBUG]%s failed unmarsheling challenge message data: %s", CallerInfo(), err.Error())
		return nil, err
	}

	if cm.NegotiateFlags.Has(negotiateFlagNTLMSSPNEGOTIATELMKEY) {
		log.Printf("[DEBUG]%s only ntlm v2 is supported, but server requested v1", CallerInfo())
		return nil, errors.New("only ntlm v2 is supported, but server requested v1 (NTLMSSP_NEGOTIATE_LM_KEY)")
	}
	if cm.NegotiateFlags.Has(negotiateFlagNTLMSSPNEGOTIATEKEYEXCH) {
		log.Printf("[DEBUG]%s key exchange requested but not supported", CallerInfo())
		return nil, errors.New("key exchange requested but not supported (NTLMSSP_NEGOTIATE_KEY_EXCH)")
	}

	if !domainNeeded {
		cm.TargetName = ""
	}

	am := authenicateMessage{
		UserName:       user,
		TargetName:     cm.TargetName,
		NegotiateFlags: cm.NegotiateFlags,
	}

	timestamp := cm.TargetInfo[avIDMsvAvTimestamp]
	if timestamp == nil { // no time sent, take current time
		ft := uint64(time.Now().UnixNano()) / 100
		ft += 116444736000000000 // add time between unix & windows offset
		timestamp = make([]byte, 8)
		binary.LittleEndian.PutUint64(timestamp, ft)
	}

	clientChallenge := make([]byte, 8)
	rand.Reader.Read(clientChallenge)

	ntlmV2Hash := getNtlmV2Hash(password, user, cm.TargetName)

	am.NtChallengeResponse = computeNtlmV2Response(ntlmV2Hash,
		cm.ServerChallenge[:], clientChallenge, timestamp, cm.TargetInfoRaw)

	if cm.TargetInfoRaw == nil {
		am.LmChallengeResponse = computeLmV2Response(ntlmV2Hash,
			cm.ServerChallenge[:], clientChallenge)
	}
	return am.MarshalBinary()
}

func ProcessChallengeWithHash(challengeMessageData []byte, user, hash string) ([]byte, error) {
	if user == "" && hash == "" {
		log.Printf("[DEBUG]%s anonymous authentication not supported", CallerInfo())
		return nil, errors.New("anonymous authentication not supported")
	}

	var cm challengeMessage
	if err := cm.UnmarshalBinary(challengeMessageData); err != nil {
		log.Printf("[DEBUG]%s failed unmarshaling challenge message data: %s", CallerInfo(), err.Error())
		return nil, err
	}

	if cm.NegotiateFlags.Has(negotiateFlagNTLMSSPNEGOTIATELMKEY) {
		log.Printf("[DEBUG]%s only ntlm v2 is supported, but server requested v1", CallerInfo())
		return nil, errors.New("only ntlm v2 is supported, but server requested v1 (NTLMSSP_NEGOTIATE_LM_KEY)")
	}
	if cm.NegotiateFlags.Has(negotiateFlagNTLMSSPNEGOTIATEKEYEXCH) {
		log.Printf("[DEBUG]%s key exchange requested but not supported", CallerInfo())
		return nil, errors.New("key exchange requested but not supported (NTLMSSP_NEGOTIATE_KEY_EXCH)")
	}

	am := authenicateMessage{
		UserName:       user,
		TargetName:     cm.TargetName,
		NegotiateFlags: cm.NegotiateFlags,
	}

	timestamp := cm.TargetInfo[avIDMsvAvTimestamp]
	if timestamp == nil { // no time sent, take current time
		ft := uint64(time.Now().UnixNano()) / 100
		ft += 116444736000000000 // add time between unix & windows offset
		timestamp = make([]byte, 8)
		binary.LittleEndian.PutUint64(timestamp, ft)
	}

	clientChallenge := make([]byte, 8)
	rand.Reader.Read(clientChallenge)

	hashParts := strings.Split(hash, ":")
	if len(hashParts) > 1 {
		hash = hashParts[1]
	}
	hashBytes, err := hex.DecodeString(hash)
	if err != nil {
		log.Printf("[DEBUG]%s failed decoding hash: %s", CallerInfo(), err.Error())
		return nil, err
	}
	ntlmV2Hash := hmacMd5(hashBytes, toUnicode(strings.ToUpper(user)+cm.TargetName))

	am.NtChallengeResponse = computeNtlmV2Response(ntlmV2Hash,
		cm.ServerChallenge[:], clientChallenge, timestamp, cm.TargetInfoRaw)

	if cm.TargetInfoRaw == nil {
		am.LmChallengeResponse = computeLmV2Response(ntlmV2Hash,
			cm.ServerChallenge[:], clientChallenge)
	}
	return am.MarshalBinary()
}
