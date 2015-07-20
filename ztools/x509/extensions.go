// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

import (
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"net"

	"github.com/zmap/zgrab/ztools/x509/pkix"
)

var (
	oidExtKeyUsage            = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidExtBasicConstraints    = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidExtSubjectAltName      = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidExtNameConstraints     = asn1.ObjectIdentifier{2, 5, 29, 30}
	oidCRLDistributionPoints  = asn1.ObjectIdentifier{2, 5, 29, 31}
	oidExtAuthKeyId           = asn1.ObjectIdentifier{2, 5, 29, 35}
	oidExtExtendedKeyUsage    = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidExtCertificatePolicy   = asn1.ObjectIdentifier{2, 5, 29, 32}
	oidExtAuthorityInfoAccess = oidExtensionAuthorityInfoAccess
)

type encodedKnownExtensions struct {
	KeyUsage              KeyUsage              `json:"key_usage,omitempty"`
	BasicConstraints      *BasicConstraints     `json:"basic_constraints,omitempty"`
	SubjectAltName        *SubjectAltName       `json:"subject_alt_name,omitempty"`
	NameConstriants       *NameConstriants      `json:"name_constraints,omitempty"`
	CRLDistributionPoints CRLDistributionPoints `json:"crl_distribution_points,omitempty"`
	AuthKeyID             AuthKeyId             `json:"authority_key_id,omitempty"`
	ExtendedKeyUsage      ExtendedKeyUsage      `json:"extended_key_usage,omitempty"`
	CertificatePolicies   CertificatePolicies   `json:"certificate_policies,omitempty"`
	AuthorityInfoAccess   *AuthorityInfoAccess  `json:"authority_info_access,omitempty"`
}

type encodedUnknownExtensions []encodedUnknownExtension

type CertificateExtensions struct {
	KeyUsage              KeyUsage              `json:"key_usage,omitempty"`
	BasicConstraints      *BasicConstraints     `json:"basic_constraints,omitempty"`
	SubjectAltName        *SubjectAltName       `json:"subject_alt_name,omitempty"`
	NameConstriants       *NameConstriants      `json:"name_constraints,omitempty"`
	CRLDistributionPoints CRLDistributionPoints `json:"crl_distribution_points,omitempty"`
	AuthKeyID             AuthKeyId             `json:"authority_key_id,omitempty"`
	ExtendedKeyUsage      ExtendedKeyUsage      `json:"extended_key_usage,omitempty"`
	CertificatePolicies   CertificatePolicies   `json:"certificate_policies,omitmepty"`
	AuthorityInfoAccess   *AuthorityInfoAccess  `json:"authority_info_access,omitempty"`
}

type UnknownCertificateExtensions []pkix.Extension

type encodedUnknownExtension struct {
	OID      string `json:"oid"`
	Critical bool   `json:"critical"`
	Value    []byte `json:"raw,omitempty"`
}

type BasicConstraints struct {
	IsCA       bool `json:"is_ca"`
	MaxPathLen *int `json:"max_path_len,omitempty"`
}

type SubjectAltName struct {
	DNSNames       []string `json:"dns_names,omitempty"`
	EmailAddresses []string `json:"email_addresses,omitempty"`
	IPAddresses    []net.IP `json:"ip_addresses,omitempty"`
}

// TODO: Handle excluded names

type NameConstriants struct {
	Critical       bool     `json:"critical"`
	PermittedNames []string `json:"permitted_names,omitempty"`
}

type CRLDistributionPoints []string

type AuthKeyId []byte

func (akid AuthKeyId) MarshalJSON() ([]byte, error) {
	enc := hex.EncodeToString(akid)
	return json.Marshal(enc)
}

type ExtendedKeyUsage []ExtKeyUsage

type CertificatePolicies []asn1.ObjectIdentifier

func (cp CertificatePolicies) MarshalJSON() ([]byte, error) {
	out := make([]string, len(cp))
	for idx, oid := range cp {
		out[idx] = oid.String()
	}
	return json.Marshal(out)
}

// TODO pull out other types
type AuthorityInfoAccess struct {
	OCSPServer            []string `json:"ocsp_urls,omitempty"`
	IssuingCertificateURL []string `json:"issuer_urls,omitempty"`
}

func (c *Certificate) jsonifyExtensions() (*CertificateExtensions, UnknownCertificateExtensions) {
	exts := new(CertificateExtensions)
	unk := make([]pkix.Extension, 0, 2)
	for _, e := range c.Extensions {
		if e.Id.Equal(oidExtKeyUsage) {
			exts.KeyUsage = c.KeyUsage
		} else if e.Id.Equal(oidExtBasicConstraints) {
			exts.BasicConstraints = new(BasicConstraints)
			exts.BasicConstraints.IsCA = c.IsCA
			if c.MaxPathLen > 0 || c.MaxPathLenZero {
				exts.BasicConstraints.MaxPathLen = new(int)
				*exts.BasicConstraints.MaxPathLen = c.MaxPathLen
			}
		} else if e.Id.Equal(oidExtSubjectAltName) {
			exts.SubjectAltName = new(SubjectAltName)
			exts.SubjectAltName.DNSNames = c.DNSNames
			exts.SubjectAltName.EmailAddresses = c.EmailAddresses
			exts.SubjectAltName.IPAddresses = c.IPAddresses
		} else if e.Id.Equal(oidExtNameConstraints) {
			exts.NameConstriants = new(NameConstriants)
			exts.NameConstriants.Critical = c.PermittedDNSDomainsCritical
			exts.NameConstriants.PermittedNames = c.PermittedDNSDomains
		} else if e.Id.Equal(oidCRLDistributionPoints) {
			exts.CRLDistributionPoints = c.CRLDistributionPoints
		} else if e.Id.Equal(oidExtAuthKeyId) {
			exts.AuthKeyID = c.AuthorityKeyId
		} else if e.Id.Equal(oidExtExtendedKeyUsage) {
			exts.ExtendedKeyUsage = c.ExtKeyUsage
		} else if e.Id.Equal(oidExtCertificatePolicy) {
			exts.CertificatePolicies = c.PolicyIdentifiers
		} else if e.Id.Equal(oidExtAuthorityInfoAccess) {
			exts.AuthorityInfoAccess = new(AuthorityInfoAccess)
			exts.AuthorityInfoAccess.OCSPServer = c.OCSPServer
			exts.AuthorityInfoAccess.IssuingCertificateURL = c.IssuingCertificateURL
		} else {
			// Unknown extension
			unk = append(unk, e)
		}
	}
	return exts, unk
}
