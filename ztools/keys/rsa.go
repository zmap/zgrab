package keys

import (
	"crypto/rsa"
	"encoding/json"
	"math/big"
)

type RSAPublicKey struct {
	rsa.PublicKey
}

type auxRSAPublicKey struct {
	Exponent int    `json:"exponent"`
	Modulus  []byte `json:"modulus"`
}

func (rp *RSAPublicKey) MarshalJSON() ([]byte, error) {
	aux := auxRSAPublicKey{
		Exponent: rp.E,
		Modulus:  rp.N.Bytes(),
	}
	return json.Marshal(&aux)
}

func (rp *RSAPublicKey) UnmarshalJSON(b []byte) error {
	var aux auxRSAPublicKey
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	rp.E = aux.Exponent
	rp.N = big.NewInt(0).SetBytes(aux.Modulus)
	return nil
}
