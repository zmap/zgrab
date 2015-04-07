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
