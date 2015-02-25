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

type CertificateExtensions struct {
	KeyUsage              KeyUsage
	BasicConstraints      *BasicConstraints
	SubjectAltName        *SubjectAltName
	NameConstriants       *NameConstriants
	CRLDistributionPoints CRLDistributionPoints
	AuthKeyId             AuthKeyId
	ExtendedKeyUsage      ExtendedKeyUsage
	CertificatePolicies   CertificatePolicies
	AuthorityInfoAccess   *AuthorityInfoAccess
	UnknownExtensions     []pkix.Extension
}

type jsonUnknownExtension struct {
	Critical bool   `json:"critical"`
	Value    []byte `json:"value"`
}

func (ce *CertificateExtensions) MarshalJSON() ([]byte, error) {
	enc := make(map[string]interface{})
	if ce.KeyUsage != 0 {
		enc["key_usage"] = ce.KeyUsage
	}
	if ce.BasicConstraints != nil {
		enc["basic_constraints"] = ce.BasicConstraints
	}
	if ce.SubjectAltName != nil {
		enc["subject_alt_name"] = ce.SubjectAltName
	}
	if ce.CRLDistributionPoints != nil {
		enc["crl_distribution_points"] = ce.CRLDistributionPoints
	}
	if ce.AuthKeyId != nil {
		enc["authority_key_id"] = ce.AuthKeyId
	}
	if ce.ExtendedKeyUsage != nil {
		enc["extended_key_usage"] = ce.ExtendedKeyUsage
	}
	if ce.CertificatePolicies != nil {
		enc["certificate_policies"] = ce.CertificatePolicies
	}
	if ce.AuthorityInfoAccess != nil {
		enc["authority_info_access"] = ce.AuthorityInfoAccess
	}
	for _, e := range ce.UnknownExtensions {
		unk := jsonUnknownExtension{
			Critical: e.Critical,
			Value:    e.Value,
		}
		enc[e.Id.String()] = unk
	}
	return json.Marshal(enc)
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
	PermittedNames []string `json:"permitted_names"`
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

func (c *Certificate) jsonifyExtensions() *CertificateExtensions {
	exts := new(CertificateExtensions)
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
			exts.AuthKeyId = c.AuthorityKeyId
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
			exts.UnknownExtensions = append(exts.UnknownExtensions, e)
		}
	}
	return exts
}
