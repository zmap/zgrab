package x509

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"time"

	"github.com/zmap/zgrab/ztools/x509/pkix"
)

func (k KeyUsage) MarshalJSON() ([]byte, error) {
	enc := make(map[string]interface{})
	enc["value"] = int(k)
	if k&KeyUsageDigitalSignature > 0 {
		enc["digital_signature"] = true
	}
	if k&KeyUsageContentCommitment > 0 {
		enc["content_commitment"] = true
	}
	if k&KeyUsageKeyEncipherment > 0 {
		enc["key_encipherment"] = true
	}
	if k&KeyUsageDataEncipherment > 0 {
		enc["data_encipherment"] = true
	}
	if k&KeyUsageKeyAgreement > 0 {
		enc["key_agreement"] = true
	}
	if k&KeyUsageCertSign > 0 {
		enc["cert_sign"] = true
	}
	if k&KeyUsageCRLSign > 0 {
		enc["crl_sign"] = true
	}
	if k&KeyUsageEncipherOnly > 0 {
		enc["encipher_only"] = true
	}
	if k&KeyUsageDecipherOnly > 0 {
		enc["decipher_only"] = true
	}
	return json.Marshal(enc)
}

func (s SignatureAlgorithm) MarshalJSON() ([]byte, error) {
	if s >= total_signature_algorithms || s < 0 {
		s = UnknownSignatureAlgorithm
	}
	name := signatureAlgorithmNames[s]
	return json.Marshal(name)
}

func (p PublicKeyAlgorithm) MarshalJSON() ([]byte, error) {
	if p >= total_key_algorithms || p < 0 {
		p = 0
	}
	name := keyAlgorithmNames[p]
	return json.Marshal(name)
}

type jsonValidity struct {
	NotBefore time.Time `json:"start"`
	NotAfter  time.Time `json:"end"`
}

type jsonSubjectKeyInfo struct {
	KeyAlgorithm interface{}            `json:"key_algorithm"`
	PublicKey    map[string]interface{} `json:"public_key"`
}

func (jv *jsonValidity) MarshalJSON() ([]byte, error) {
	start := jv.NotBefore.Format(time.RFC3339)
	end := jv.NotAfter.Format(time.RFC3339)
	s := fmt.Sprintf(`{"start":"%s","end":"%s"}`, start, end)
	return []byte(s), nil
}

type jsonTBSCertificate struct {
	Version            int                    `json:"version"`
	SerialNumber       string                 `json:"serial_number"`
	SignatureAlgorithm interface{}            `json:"signature_algorithm"`
	Issuer             pkix.Name              `json:"issuer"`
	Validity           jsonValidity           `json:"validity"`
	Subject            pkix.Name              `json:"subject"`
	SubjectKeyInfo     jsonSubjectKeyInfo     `json:"subject_key_info"`
	Extensions         *CertificateExtensions `json:"extensions"`
}

type jsonSignature struct {
	Value           []byte `json:"value"`
	Valid           bool   `json:"valid"`
	ValidationError string `json:"validation_error,omitempty"`
	Matches         *bool  `json:"matches_domain"`
	SelfSigned      bool   `json:"self_signed"`
}

type jsonCertificate struct {
	Certificate        jsonTBSCertificate     `json:"certificate"`
	SignatureAlgorithm interface{}            `json:"signature_algorithm"`
	Signature          jsonSignature          `json:"signature"`
	FingerprintMD5     CertificateFingerprint `json:"fingerprint_md5"`
	FingerprintSHA1    CertificateFingerprint `json:"fingerprint_sha1"`
	FingerprintSHA256  CertificateFingerprint `json:"fingerprint_sha256"`
}

func (c *Certificate) MarshalJSON() ([]byte, error) {
	// Do some name mangling for pretty output
	var algorithm interface{}
	switch c.SignatureAlgorithm {
	case UnknownSignatureAlgorithm:
		algorithm = c.SignatureAlgorithmOID.String()
	default:
		algorithm = c.SignatureAlgorithm
	}
	var key interface{}
	switch c.PublicKeyAlgorithm {
	case UnknownPublicKeyAlgorithm:
		key = c.PublicKeyAlgorithmOID.String()
	default:
		key = c.PublicKeyAlgorithm
	}
	// Fill out the certificate
	jc := new(jsonCertificate)
	jc.Certificate.Version = c.Version
	jc.Certificate.SerialNumber = c.SerialNumber.String()
	jc.Certificate.SignatureAlgorithm = algorithm
	jc.Certificate.Issuer = c.Issuer
	jc.Certificate.Validity.NotBefore = c.NotBefore
	jc.Certificate.Validity.NotAfter = c.NotAfter
	jc.Certificate.Subject = c.Subject
	jc.Certificate.SubjectKeyInfo.KeyAlgorithm = key

	// Pull out the key
	keyMap := make(map[string]interface{})

	switch key := c.PublicKey.(type) {
	case *rsa.PublicKey:
		keyMap["modulus"] = key.N.Bytes()
		keyMap["exponent"] = key.E
		keyMap["length"] = key.N.BitLen()
	case *dsa.PublicKey:
		keyMap["p"] = key.P.String()
		keyMap["q"] = key.Q.String()
		keyMap["g"] = key.G.String()
		keyMap["y"] = key.Y.String()
	case *ecdsa.PublicKey:
		params := key.Params()
		keyMap["P"] = params.P.String()
		keyMap["N"] = params.N.String()
		keyMap["B"] = params.B.String()
		keyMap["Gx"] = params.Gx.String()
		keyMap["Gy"] = params.Gy.String()
		keyMap["X"] = key.X.String()
		keyMap["Y"] = key.Y.String()
	}
	jc.Certificate.SubjectKeyInfo.PublicKey = keyMap
	jc.Certificate.Extensions = c.jsonifyExtensions()

	// TODO: Handle the fact this might not match
	jc.SignatureAlgorithm = algorithm
	jc.Signature.Value = c.Signature
	jc.Signature.Valid = c.valid
	if c.validationError != nil {
		jc.Signature.ValidationError = c.validationError.Error()
	}
	if c.Subject.CommonName == c.Issuer.CommonName {
		jc.Signature.SelfSigned = true
	}
	jc.FingerprintMD5 = c.FingerprintMD5
	jc.FingerprintSHA1 = c.FingerprintSHA1
	jc.FingerprintSHA256 = c.FingerprintSHA256
	return json.Marshal(jc)
}
