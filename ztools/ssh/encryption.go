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

type cipher interface {
	PaddingLength(plaintextLength int) int
	PadInto(dest []byte)
	Encrypt(paddedPlaintext []byte) (ciphertext []byte, err error)
}

type nullEncryption struct{}

func (n *nullEncryption) PaddingLength(plaintextLength int) int {
	r := plaintextLength % 8
	return 8 - r
}

func (n *nullEncryption) PadInto(dest []byte) {
	for idx := range dest {
		dest[idx] = 0
	}
}

func (n *nullEncryption) Encrypt(paddedPlaintext []byte) ([]byte, error) {
	if len(paddedPlaintext)%8 != 0 {
		return nil, errInvalidPlaintextLength
	}
	out := make([]byte, len(paddedPlaintext))
	copy(out, paddedPlaintext)
	return out, nil
}
