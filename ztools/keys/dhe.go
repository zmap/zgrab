package keys

import (
	"encoding/json"
	"math/big"
)

// CryptoParameter represents a big.Int used a parameter in some cryptography.
// It serializes to json as a tupe of a base64-encoded number and a length in
// bits.
type CryptoParameter struct {
	big.Int
}

type auxCryptoParameter struct {
	Raw    []byte `json:"b64"`
	Length int    `json:"bit_length"`
}

// MarshalJSON implements the json.Marshaler interface
func (p *CryptoParameter) MarshalJSON() ([]byte, error) {
	var aux auxCryptoParameter
	aux.Raw = p.Bytes()
	aux.Length = 8 * len(aux.Raw)
	return json.Marshal(&aux)
}

// UnmarshalJSON implements the json.Unmarshal interface
func (p *CryptoParameter) UnmarshalJSON(b []byte) error {
	var aux auxCryptoParameter
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	p.SetBytes(aux.Raw)
	return nil
}

// DHParams can be used to store finite-field Diffie-Hellman parameters. At any
// point in time, it is unlikely that both OurPrivate and TheirPrivate will be
// non-nil.
type DHParams struct {
	Prime        *CryptoParameter `json:"prime"`
	Generator    *CryptoParameter `json:"generator"`
	OurPublic    *CryptoParameter `json:"public_us,omitempty"`
	OurPrivate   *CryptoParameter `json:"private_us,omitempty"`
	TheirPublic  *CryptoParameter `json:"public_them,omitempty"`
	TheirPrivate *CryptoParameter `json:"private_them,omitempty"`
	SessionKey   *CryptoParameter `json:"session_key,omitempty"`
}
