package ntlmssp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"unicode/utf16"
)

// helper func's for dealing with Windows Unicode (UTF16LE)

func fromUnicode(d []byte) (string, error) {
	if len(d)%2 > 0 {
		log.Printf("[DEBUG]%s unicode (utf16le) specified, but uneven data length", CallerInfo())
		return "", errors.New("unicode (utf 16 le) specified, but uneven data length")
	}
	s := make([]uint16, len(d)/2)
	err := binary.Read(bytes.NewReader(d), binary.LittleEndian, &s)
	if err != nil {
		log.Printf("[DEBUG]%s error reading bytes: %s", CallerInfo(), err.Error())
		return "", err
	}
	return string(utf16.Decode(s)), nil
}

func toUnicode(s string) []byte {
	uints := utf16.Encode([]rune(s))
	b := bytes.Buffer{}
	binary.Write(&b, binary.LittleEndian, &uints)
	return b.Bytes()
}
