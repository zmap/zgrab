package ztls

import (
	"encoding/json"
	"math/big"
	"regexp"

	"github.com/zmap/zgrab/ztools/keys"
)

// SignatureAndHash is a signatureAndHash that implements json.Marshaler and
// json.Unmarshaler
type SignatureAndHash signatureAndHash

type auxSignatureAndHash struct {
	SignatureAlgorithm string `json:"signature_algorithm"`
	HashAlgorithm      string `json:"hash_algorithm"`
}

// MarshalJSON implements the json.Marshaler interface
func (sh *SignatureAndHash) MarshalJSON() ([]byte, error) {
	aux := auxSignatureAndHash{
		SignatureAlgorithm: nameForSignature(sh.signature),
		HashAlgorithm:      nameForHash(sh.hash),
	}
	return json.Marshal(&aux)
}

var unknownAlgorithmRegex = regexp.MustCompile(`unknown\.(\d+)`)

// UnmarshalJSON implements the json.Unmarshaler interface
func (sh *SignatureAndHash) UnmarshalJSON(b []byte) error {
	aux := new(auxSignatureAndHash)
	if err := json.Unmarshal(b, aux); err != nil {
		return err
	}
	// TODO implement
	panic("unimplemented")
	return nil
}

func (ka *dheKeyAgreement) DHParams() *keys.DHParams {
	out := new(keys.DHParams)
	if ka.p != nil {
		out.Prime = new(big.Int).Set(ka.p)
	}
	if ka.g != nil {
		out.Generator = new(big.Int).Set(ka.g)
	}
	if ka.yServer != nil {
		out.ServerPublic = new(big.Int).Set(ka.yServer)
	}
	return out
}

func (ka *rsaKeyAgreement) RSAParams() *keys.RSAPublicKey {
	out := new(keys.RSAPublicKey)
	out.PublicKey = ka.publicKey
	return out
}

type Signature struct {
	Raw              []byte
	Valid            bool
	Version          TLSVersion
	SigHashExtension *SignatureAndHash
}

func (ka *signedKeyAgreement) Signature() *Signature {
	out := Signature{
		Raw:     ka.raw,
		Valid:   ka.valid,
		Version: TLSVersion(ka.version),
	}
	if ka.version >= VersionTLS12 {
		out.SigHashExtension = new(SignatureAndHash)
		*out.SigHashExtension = SignatureAndHash(ka.sh)
	}
	return &out
}
