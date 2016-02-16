/*
 * ZGrab Copyright 2015 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package ssh

import (
	"encoding/binary"
	"encoding/json"
	"math/big"
	"strings"
)

type mpint struct {
	big.Int
}

func (mp *mpint) Marshal() ([]byte, error) {
	b := mp.Bytes()
	if len(b) == 0 {
		b = make([]byte, 1)
	}
	if b[0] < 0x80 {
		return b, nil
	}
	out := make([]byte, len(b)+1)
	out[0] = 0x00
	copy(out[1:], b)
	return out, nil
}

func (mp *mpint) Unmarshal(raw []byte) ([]byte, bool) {
	b := raw
	if len(b) < 4 {
		return raw, false
	}
	mpLength := binary.BigEndian.Uint32(b)
	b = b[4:]
	if mpLength > uint32(len(b)) {
		return raw, false
	}
	mp.SetBytes(b[0:mpLength])
	b = b[mpLength:]
	return b, true
}

func (mp *mpint) MarshalJSON() ([]byte, error) {
	b := mp.Bytes()
	return json.Marshal(b)
}

func (mp *mpint) UnmarshalJSON(raw []byte) error {
	var b []byte
	if err := json.Unmarshal(raw, b); err != nil {
		return err
	}
	mp.SetBytes(b)
	return nil
}

// Packet represents an SSH binary packet. See RFC
type packet struct {
	packetLength  uint32
	paddingLength uint8
	msgType       byte
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

func (n *NameList) MarshaledLength() int {
	// 4 bytes for encoding the length
	length := 4
	nameCount := len(*n)

	// No body if its empty
	if nameCount <= 0 {
		return length
	}

	// 1 byte per comma
	length += nameCount - 1

	// Add in lengths of string
	for _, val := range *n {
		length += len(val)
	}
	return length
}

func (n *NameList) MarshalInto(dest []byte) ([]byte, error) {
	b := dest
	if len(b) < 4 {
		return dest, errShortBuffer
	}
	b = b[4:]
	joined := strings.Join(*n, ",")
	if len(b) < len(joined) {
		return dest, errShortBuffer
	}
	length := len(joined)
	binary.BigEndian.PutUint32(dest, uint32(length))
	copy(b, joined[:])
	b = b[length:]
	return b, nil
}

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
