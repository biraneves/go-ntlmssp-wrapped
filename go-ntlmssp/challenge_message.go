package ntlmssp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
)

type challengeMessageFields struct {
	messageHeader
	TargetName      varField
	NegotiateFlags  negotiateFlags
	ServerChallenge [8]byte
	_               [8]byte
	TargetInfo      varField
}

func (m challengeMessageFields) IsValid() bool {
	return m.messageHeader.IsValid() && m.MessageType == 2
}

type challengeMessage struct {
	challengeMessageFields
	TargetName    string
	TargetInfo    map[avID][]byte
	TargetInfoRaw []byte
}

func (m *challengeMessage) UnmarshalBinary(data []byte) error {
	r := bytes.NewReader(data)
	err := binary.Read(r, binary.LittleEndian, &m.challengeMessageFields)
	if err != nil {
		log.Printf("[DEBUG]%s error reading challenge message field: %s", CallerInfo(), err.Error())
		return err
	}
	if !m.challengeMessageFields.IsValid() {
		log.Printf("[DEBUG]%s message is not a valid challenge message: %+v", CallerInfo(), m.challengeMessageFields.messageHeader)
		return fmt.Errorf("message is not a valid challenge message: %+v", m.challengeMessageFields.messageHeader)
	}

	if m.challengeMessageFields.TargetName.Len > 0 {
		m.TargetName, err = m.challengeMessageFields.TargetName.ReadStringFrom(data, m.NegotiateFlags.Has(negotiateFlagNTLMSSPNEGOTIATEUNICODE))
		if err != nil {
			log.Printf("[DEBUG]%s error reading negotiate flag: %s", CallerInfo(), err.Error())
			return err
		}
	}

	if m.challengeMessageFields.TargetInfo.Len > 0 {
		d, err := m.challengeMessageFields.TargetInfo.ReadFrom(data)
		m.TargetInfoRaw = d
		if err != nil {
			log.Printf("[DEBUG]%s error reading target info: %s", CallerInfo(), err.Error())
			return err
		}
		m.TargetInfo = make(map[avID][]byte)
		r := bytes.NewReader(d)
		for {
			var id avID
			var l uint16
			err = binary.Read(r, binary.LittleEndian, &id)
			if err != nil {
				log.Printf("[DEBUG]%s error reading id: %s", CallerInfo(), err.Error())
				return err
			}
			if id == avIDMsvAvEOL {
				break
			}

			err = binary.Read(r, binary.LittleEndian, &l)
			if err != nil {
				log.Printf("[DEBUG]%s error reading l: %s", CallerInfo(), err.Error())
				return err
			}
			value := make([]byte, l)
			n, err := r.Read(value)
			if err != nil {
				log.Printf("[DEBUG]%s error reading binary l: %s", CallerInfo(), err.Error())
				return err
			}
			if n != int(l) {
				log.Printf("[DEBUG]%s expected to read %d bytes, got only %d", CallerInfo(), l, n)
				return fmt.Errorf("expected to read %d bytes, got only %d", l, n)
			}
			m.TargetInfo[id] = value
		}
	}

	return nil
}
