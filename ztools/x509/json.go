// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/asn1"
	"encoding/json"
	"time"

	"github.com/zmap/zgrab/ztools/keys"
	"github.com/zmap/zgrab/ztools/x509/pkix"
)

type auxKeyUsage struct {
	DigitalSignature  bool   `json:"digital_signature,omitempty"`
	ContentCommitment bool   `json:"content_commitment,omitempty"`
	KeyEncipherment   bool   `json:"key_encipherment,omitempty"`
	DataEncipherment  bool   `json:"data_encipherment,omitempty"`
	KeyAgreement      bool   `json:"key_agreement,omitempty"`
	CertificateSign   bool   `json:"certificate_sign,omitempty"`
	CRLSign           bool   `json:"crl_sign,omitempty"`
	EncipherOnly      bool   `json:"encipher_only,omitempty"`
	DecipherOnly      bool   `json:"decipher_only,omitempty"`
	Value             uint32 `json:"value"`
}

// MarshalJSON implements the json.Marshaler interface
func (k KeyUsage) MarshalJSON() ([]byte, error) {
	var enc auxKeyUsage
	enc.Value = uint32(k)
	if k&KeyUsageDigitalSignature > 0 {
		enc.DigitalSignature = true
	}
	if k&KeyUsageContentCommitment > 0 {
		enc.ContentCommitment = true
	}
	if k&KeyUsageKeyEncipherment > 0 {
		enc.KeyEncipherment = true
	}
	if k&KeyUsageDataEncipherment > 0 {
		enc.DataEncipherment = true
	}
	if k&KeyUsageKeyAgreement > 0 {
		enc.KeyAgreement = true
	}
	if k&KeyUsageCertSign > 0 {
		enc.CertificateSign = true
	}
	if k&KeyUsageCRLSign > 0 {
		enc.CRLSign = true
	}
	if k&KeyUsageEncipherOnly > 0 {
		enc.EncipherOnly = true
	}
	if k&KeyUsageDecipherOnly > 0 {
		enc.DecipherOnly = true
	}
	return json.Marshal(&enc)
}

// UnmarshalJSON implements the json.Unmarshler interface
func (k *KeyUsage) UnmarshalJSON(b []byte) error {
	var aux auxKeyUsage
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	// TODO: validate the flags match
	v := int(aux.Value)
	*k = KeyUsage(v)
	return nil
}

type auxSignatureAlgorithm struct {
	Name string      `json:"name,omitempty"`
	OID  pkix.AuxOID `json:"oid"`
}

// MarshalJSON implements the json.Marshaler interface
func (s *SignatureAlgorithm) MarshalJSON() ([]byte, error) {
	aux := auxSignatureAlgorithm{
		Name: s.String(),
	}
	for _, val := range signatureAlgorithmDetails {
		if val.algo == *s {
			aux.OID = make([]int, len(val.oid))
			for idx := range val.oid {
				aux.OID[idx] = val.oid[idx]
			}
		}
	}
	return json.Marshal(&aux)
}

// UnmarshalJSON implements the json.Unmarshler interface
func (s *SignatureAlgorithm) UnmarshalJSON(b []byte) error {
	var aux auxSignatureAlgorithm
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	*s = UnknownSignatureAlgorithm
	oid := asn1.ObjectIdentifier(aux.OID.AsSlice())
	for _, val := range signatureAlgorithmDetails {
		if val.oid.Equal(oid) {
			*s = val.algo
			break
		}
	}
	return nil
}

type auxPublicKeyAlgorithm struct {
	Name string      `json:"name,omitempty"`
	OID  pkix.AuxOID `json:"oid"`
}

// MarshalJSON implements the json.Marshaler interface
func (p *PublicKeyAlgorithm) MarshalJSON() ([]byte, error) {
	aux := auxPublicKeyAlgorithm{
		Name: p.String(),
	}
	return json.Marshal(&aux)
}

// UnmarshalJSON implements the json.Unmarshaler interface
func (p *PublicKeyAlgorithm) UnmarshalJSON(b []byte) error {
	var aux auxPublicKeyAlgorithm
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	panic("unimplemented")
}

type auxValidity struct {
	Start string `json:"start"`
	End   string `json:"end"`
}

func (v *validity) MarshalJSON() ([]byte, error) {
	aux := auxValidity{
		Start: v.NotBefore.UTC().Format(time.RFC3339),
		End:   v.NotAfter.UTC().Format(time.RFC3339),
	}
	return json.Marshal(&aux)
}

func (v *validity) UnmarshalJSON(b []byte) error {
	var aux auxValidity
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	var err error
	if v.NotBefore, err = time.Parse(time.RFC3339, aux.Start); err != nil {
		return err
	}
	if v.NotAfter, err = time.Parse(time.RFC3339, aux.End); err != nil {
		return err
	}
	return nil
}

type jsonSubjectKeyInfo struct {
	KeyAlgorithm   PublicKeyAlgorithm `json:"key_algorithm"`
	RSAPublicKey   *keys.RSAPublicKey `json:"rsa_public_key,omitempty"`
	DSAPublicKey   interface{}        `json:"dsa_public_key,omitempty"`
	ECDSAPublicKey interface{}        `json:"ecdsa_public_key,omitempty"`
}

type jsonSignature struct {
	SignatureAlgorithm SignatureAlgorithm `json:"signature_algorithm"`
	Value              []byte             `json:"value"`
	Valid              bool               `json:"valid"`
	SelfSigned         bool               `json:"self_signed"`
}

type jsonCertificate struct {
	Version            int                          `json:"version"`
	SerialNumber       string                       `json:"serial_number"`
	SignatureAlgorithm SignatureAlgorithm           `json:"signature_algorithm"`
	Issuer             pkix.Name                    `json:"issuer"`
	IssuerDN           string                       `json:"issuer_dn,omitempty"`
	Validity           validity                     `json:"validity"`
	Subject            pkix.Name                    `json:"subject"`
	SubjectDN          string                       `json:"subject_dn,omitempty"`
	SubjectKeyInfo     jsonSubjectKeyInfo           `json:"subject_key_info"`
	Extensions         *CertificateExtensions       `json:"extensions,omitempty"`
	UnknownExtensions  UnknownCertificateExtensions `json:"unknown_extensions,omitempty"`
	Signature          jsonSignature                `json:"signature"`
	FingerprintMD5     CertificateFingerprint       `json:"fingerprint_md5"`
	FingerprintSHA1    CertificateFingerprint       `json:"fingerprint_sha1"`
	FingerprintSHA256  CertificateFingerprint       `json:"fingerprint_sha256"`
}

func (c *Certificate) MarshalJSON() ([]byte, error) {
	// Fill out the certificate
	jc := new(jsonCertificate)
	jc.Version = c.Version
	jc.SerialNumber = c.SerialNumber.String()
	jc.SignatureAlgorithm = c.SignatureAlgorithm
	jc.Issuer = c.Issuer
	jc.IssuerDN = c.Issuer.String()
	jc.Validity.NotBefore = c.NotBefore
	jc.Validity.NotAfter = c.NotAfter
	jc.Subject = c.Subject
	jc.SubjectDN = c.Subject.String()
	jc.SubjectKeyInfo.KeyAlgorithm = c.PublicKeyAlgorithm

	// Pull out the key
	keyMap := make(map[string]interface{})

	switch key := c.PublicKey.(type) {
	case *rsa.PublicKey:
		rsaKey := new(keys.RSAPublicKey)
		rsaKey.PublicKey = key
		jc.SubjectKeyInfo.RSAPublicKey = rsaKey
	case *dsa.PublicKey:
		keyMap["p"] = key.P.Bytes()
		keyMap["q"] = key.Q.Bytes()
		keyMap["g"] = key.G.Bytes()
		keyMap["y"] = key.Y.Bytes()
		jc.SubjectKeyInfo.DSAPublicKey = keyMap
	case *ecdsa.PublicKey:
		params := key.Params()
		keyMap["p"] = params.P.Bytes()
		keyMap["n"] = params.N.Bytes()
		keyMap["b"] = params.B.Bytes()
		keyMap["gx"] = params.Gx.Bytes()
		keyMap["gy"] = params.Gy.Bytes()
		keyMap["x"] = key.X.Bytes()
		keyMap["y"] = key.Y.Bytes()
		jc.SubjectKeyInfo.ECDSAPublicKey = keyMap
	}

	jc.Extensions, jc.UnknownExtensions = c.jsonifyExtensions()

	// TODO: Handle the fact this might not match
	jc.Signature.SignatureAlgorithm = jc.SignatureAlgorithm
	jc.Signature.Value = c.Signature
	jc.Signature.Valid = c.validSignature
	if c.Subject.CommonName == c.Issuer.CommonName {
		jc.Signature.SelfSigned = true
	}
	jc.FingerprintMD5 = c.FingerprintMD5
	jc.FingerprintSHA1 = c.FingerprintSHA1
	jc.FingerprintSHA256 = c.FingerprintSHA256
	return json.Marshal(jc)
}
