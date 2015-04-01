package ssh

import (
	"encoding/binary"
	"strings"
)

// Packet represents an SSH binary packet. See RFC
type packet struct {
	packetLength  uint32
	paddingLength uint8
	payload       []byte
	padding       []byte
	mac           []byte
}

func expectedLength(packetLength uint32, macLength uint32) int {
	totalLength := packetLength + macLength + 4
	return int(totalLength)
}

// NameList represents the name-list structure described in RFC 4251.
// See https://tools.ietf.org/html/rfc4251 for details.
type NameList []string

// Unmarshal a NameList from a byte slice of the form
// [length:body:extra] where extra is optional. Returns [extra], true
// when successful, and raw, false when unsuccessful.
func (n *NameList) Unmarshal(raw []byte) ([]byte, bool) {
	b := raw
	if len(b) < 4 {
		return raw, false
	}
	length := binary.BigEndian.Uint32(b)
	b = b[4:]
	if uint32(len(b)) < length {
		return raw, false
	}
	s := string(b[0:length])
	if len(s) == 0 {
		*n = make([]string, 0)
	} else {
		*n = NameList(strings.Split(s, ","))
	}
	b = b[length:]
	return b, true
}
