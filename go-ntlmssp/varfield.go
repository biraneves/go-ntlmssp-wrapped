package ntlmssp

import (
	"errors"
	"log"
)

type varField struct {
	Len          uint16
	MaxLen       uint16
	BufferOffset uint32
}

func (f varField) ReadFrom(buffer []byte) ([]byte, error) {
	if len(buffer) < int(f.BufferOffset+uint32(f.Len)) {
		log.Printf("[DEBUG]%s error reading data, varfield extends beyond buffer", CallerInfo())
		return nil, errors.New("error reading data, varField extends beyond buffer")
	}
	return buffer[f.BufferOffset : f.BufferOffset+uint32(f.Len)], nil
}

func (f varField) ReadStringFrom(buffer []byte, unicode bool) (string, error) {
	d, err := f.ReadFrom(buffer)
	if err != nil {
		log.Printf("[DEBUG]%s error reading from buffer: %s", CallerInfo(), err.Error())
		return "", err
	}
	if unicode { // UTF-16LE encoding scheme
		return fromUnicode(d)
	}
	// OEM encoding, close enough to ASCII, since no code page is specified
	return string(d), err
}

func newVarField(ptr *int, fieldsize int) varField {
	f := varField{
		Len:          uint16(fieldsize),
		MaxLen:       uint16(fieldsize),
		BufferOffset: uint32(*ptr),
	}
	*ptr += fieldsize
	return f
}
