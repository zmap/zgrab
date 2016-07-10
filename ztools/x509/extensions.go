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
	"github.com/zmap/zgrab/ztools/zct"
)

var (
	oidExtKeyUsage           = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidExtBasicConstraints   = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidExtSubjectAltName     = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidExtNameConstraints    = asn1.ObjectIdentifier{2, 5, 29, 30}
	oidCRLDistributionPoints = asn1.ObjectIdentifier{2, 5, 29, 31}
	oidExtAuthKeyId          = asn1.ObjectIdentifier{2, 5, 29, 35}
	oidExtSubjectKeyId       = asn1.ObjectIdentifier{2, 5, 29, 14}
	oidExtExtendedKeyUsage   = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidExtCertificatePolicy  = asn1.ObjectIdentifier{2, 5, 29, 32}

	oidExtAuthorityInfoAccess            = oidExtensionAuthorityInfoAccess
	oidExtensionCTPrecertificatePoison   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3}
	oidExtSignedCertificateTimestampList = oidExtensionSignedCertificateTimestampList
)

type encodedUnknownExtensions []encodedUnknownExtension

type CertificateExtensions struct {
	KeyUsage                       KeyUsage                         `json:"key_usage,omitempty"`
	BasicConstraints               *BasicConstraints                `json:"basic_constraints,omitempty"`
	SubjectAltName                 *SubjectAltName                  `json:"subject_alt_name,omitempty"`
	NameConstraints                *NameConstraints                 `json:"name_constraints,omitempty"`
	CRLDistributionPoints          CRLDistributionPoints            `json:"crl_distribution_points,omitempty"`
	AuthKeyID                      SubjAuthKeyId                    `json:"authority_key_id,omitempty"`
	SubjectKeyID                   SubjAuthKeyId                    `json:"subject_key_id,omitempty"`
	ExtendedKeyUsage               ExtendedKeyUsage                 `json:"extended_key_usage,omitempty"`
	CertificatePolicies            CertificatePolicies              `json:"certificate_policies,omitmepty"`
	AuthorityInfoAccess            *AuthorityInfoAccess             `json:"authority_info_access,omitempty"`
	IsPrecert                      IsPrecert                        `json:"ct_poison,omitempty"`
	SignedCertificateTimestampList []*ct.SignedCertificateTimestamp `json:"signed_certificate_timestamps,omitempty"`
}

type UnknownCertificateExtensions []pkix.Extension

type encodedUnknownExtension struct {
	OID      string `json:"oid"`
	Critical bool   `json:"critical"`
	Value    []byte `json:"raw,omitempty"`
}

type IsPrecert bool

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

type NameConstraints struct {
	Critical bool `json:"critical"`

	PermittedDNSDomains     []string    `json:"permitted_names,omitempty"`
	PermittedEmailDomains   []string    `json:"permitted_email_addresses,omitempty"`
	PermittedIPAddresses    []net.IPNet `json:"permitted_ip_addresses,omitempty"`
	PermittedDirectoryNames []pkix.Name `json:"permitted_directory_names,omitempty"`

	ExcludedEmailDomains   []string    `json:"excluded_names,omitempty"`
	ExcludedDNSDomains     []string    `json:"excluded_email_addresses,omitempty"`
	ExcludedIPAddresses    []net.IPNet `json:"excluded_ip_addresses,omitempty"`
	ExcludedDirectoryNames []pkix.Name `json:"excluded_directory_names,omitempty"`
}

type NameConstraintsJSON struct {
	Critical bool `json:"critical"`

	PermittedDNSDomains     []string    `json:"permitted_names,omitempty"`
	PermittedEmailDomains   []string    `json:"permitted_email_addresses,omitempty"`
	PermittedIPAddresses    []string    `json:"permitted_ip_addresses,omitempty"`
	PermittedDirectoryNames []pkix.Name `json:"permitted_directory_names,omitempty"`

	ExcludedEmailDomains   []string    `json:"excluded_names,omitempty"`
	ExcludedDNSDomains     []string    `json:"excluded_email_addresses,omitempty"`
	ExcludedIPAddresses    []string    `json:"excluded_ip_addresses,omitempty"`
	ExcludedDirectoryNames []pkix.Name `json:"excluded_directory_names,omitempty"`
}

func (nc NameConstraints) MarshalJSON() ([]byte, error) {
	var out NameConstraintsJSON
	out.PermittedDNSDomains = nc.PermittedDNSDomains
	out.PermittedEmailDomains = nc.PermittedEmailDomains
	out.PermittedIPAddresses = make([]string, len(nc.PermittedIPAddresses))
	for _, ip := range nc.PermittedIPAddresses {
		out.PermittedIPAddresses = append(out.PermittedIPAddresses, ip.String())
	}
	out.ExcludedDNSDomains = nc.ExcludedDNSDomains
	out.ExcludedEmailDomains = nc.ExcludedEmailDomains
	out.ExcludedIPAddresses = make([]string, len(nc.ExcludedIPAddresses))
	for _, ip := range nc.ExcludedIPAddresses {
		out.ExcludedIPAddresses = append(out.ExcludedIPAddresses, ip.String())
	}
	return json.Marshal(out)
}

type CRLDistributionPoints []string

type SubjAuthKeyId []byte

func (kid SubjAuthKeyId) MarshalJSON() ([]byte, error) {
	enc := hex.EncodeToString(kid)
	return json.Marshal(enc)
}

type ExtendedKeyUsage []ExtKeyUsage

type CertificatePolicies []asn1.ObjectIdentifier

// UNION of Chromium (https://chromium.googlesource.com/chromium/src/net/+/master/cert/ev_root_ca_metadata.cc)
// and Firefox (http://hg.mozilla.org/mozilla-central/file/tip/security/certverifier/ExtendedValidation.cpp) EV OID lists
var ExtendedValidationOIDs = []asn1.ObjectIdentifier{
	// CA/Browser Forum EV OID standard
	// https://cabforum.org/object-registry/
	asn1.ObjectIdentifier{2, 23, 140, 1, 1},
	// CA/Browser Forum EV Code Signing
	asn1.ObjectIdentifier{2, 23, 140, 1, 3},
	// CA/Browser Forum .onion EV Certs
	asn1.ObjectIdentifier{2, 23, 140, 1, 31},
	// AC Camerfirma S.A. Chambers of Commerce Root - 2008
	// https://www.camerfirma.com
	// AC Camerfirma uses the last two arcs to track how the private key
	// is managed - the effective verification policy is the same.
	asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 17326, 10, 14, 2, 1, 2},
	asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 17326, 10, 14, 2, 2, 2},
	// AC Camerfirma S.A. Global Chambersign Root - 2008
	// https://server2.camerfirma.com:8082
	// AC Camerfirma uses the last two arcs to track how the private key
	// is managed - the effective verification policy is the same.
	asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 17326, 10, 8, 12, 1, 2},
	asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 17326, 10, 8, 12, 2, 2},
	// AddTrust External CA Root
	// https://addtrustexternalcaroot-ev.comodoca.com
	asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 6449, 1, 2, 1, 5, 1},
	// This is the Network Solutions EV OID. However, this root
	// cross-certifies NetSol and so we need it here too.
	asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 782, 1, 2, 1, 8, 1},
	// Actalis Authentication Root CA
	// https://ssltest-a.actalis.it:8443
	asn1.ObjectIdentifier{1, 3, 159, 1, 17, 1},
	// AffirmTrust Commercial
	// https://commercial.affirmtrust.com/
	asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 34697, 2, 1},
	// AffirmTrust Networking
	// https://networking.affirmtrust.com:4431
	asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 34697, 2, 2},
	// AffirmTrust Premium
	// https://premium.affirmtrust.com:4432/
	asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 34697, 2, 3},
	// AffirmTrust Premium ECC
	// https://premiumecc.affirmtrust.com:4433/
	asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 34697, 2, 4},
	// Autoridad de Certificacion Firmaprofesional CIF A62634068
	// https://publifirma.firmaprofesional.com/
	asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 13177, 10, 1, 3, 10},
	// Baltimore CyberTrust Root
	// https://secure.omniroot.com/repository/
	asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 6334, 1, 100, 1},
	// Buypass Class 3 CA 1
	// https://valid.evident.ca13.ssl.buypass.no/
	asn1.ObjectIdentifier{2, 16, 578, 1, 26, 1, 3, 3},
	// Buypass Class 3 Root CA
	// https://valid.evident.ca23.ssl.buypass.no/
	asn1.ObjectIdentifier{2, 16, 578, 1, 26, 1, 3, 3},
	// CA 沃通根证书
	// https://root2evtest.wosign.com/
	asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 36305, 2},
	// Certification Authority of WoSign
	// https://root1evtest.wosign.com/
	asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 36305, 2},
	// CertPlus Class 2 Primary CA (KEYNECTIS)
	// https://www.keynectis.com/
	asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 22234, 2, 5, 2, 3, 1},
	// Certum Trusted Network CA
	// https://juice.certum.pl/
	asn1.ObjectIdentifier{1, 2, 616, 1, 113527, 2, 5, 1, 1},
	// China Internet Network Information Center EV Certificates Root
	// https://evdemo.cnnic.cn/
	asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 29836, 1, 10},
	// COMODO Certification Authority
	// https://secure.comodo.com/
	asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 6449, 1, 2, 1, 5, 1},
	// COMODO Certification Authority (reissued certificate with NotBefore of
	// Jan 1 00:00:00 2011 GMT)
	// https://secure.comodo.com/
	asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 6449, 1, 2, 1, 5, 1},
	// COMODO ECC Certification Authority
	// https://comodoecccertificationauthority-ev.comodoca.com/
	asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 6449, 1, 2, 1, 5, 1},
	// COMODO RSA Certification Authority
	// https://comodorsacertificationauthority-ev.comodoca.com/
	asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 6449, 1, 2, 1, 5, 1},
	// Cybertrust Global Root
	// https://evup.cybertrust.ne.jp/ctj-ev-upgrader/evseal.gif
	asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 6334, 1, 100, 1},
	// DigiCert High Assurance EV Root CA
	// https://www.digicert.com
	asn1.ObjectIdentifier{2, 16, 840, 1, 114412, 2, 1},
	// D-TRUST Root Class 3 CA 2 EV 2009
	// https://certdemo-ev-valid.ssl.d-trust.net/
	asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 4788, 2, 202, 1},
	// Entrust.net Secure Server Certification Authority
	// https://www.entrust.net/
	asn1.ObjectIdentifier{2, 16, 840, 1, 114028, 10, 1, 2},
	// Entrust Root Certification Authority
	// https://www.entrust.net/
	asn1.ObjectIdentifier{2, 16, 840, 1, 114028, 10, 1, 2},
	// Equifax Secure Certificate Authority (GeoTrust)
	// https://www.geotrust.com/
	asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 14370, 1, 6},
	// E-Tugra Certification Authority
	// https://sslev.e-tugra.com.tr
	asn1.ObjectIdentifier{2, 16, 792, 3, 0, 4, 1, 1, 4},
	// GeoTrust Primary Certification Authority
	// https://www.geotrust.com/
	asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 14370, 1, 6},
	// GeoTrust Primary Certification Authority - G2
	asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 14370, 1, 6},
	// GeoTrust Primary Certification Authority - G3
	asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 14370, 1, 6},
	// GlobalSign Root CA - R2
	// https://www.globalsign.com/
	asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 4146, 1, 1},
	// GlobalSign Root CA
	asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 4146, 1, 1},
	// GlobalSign Root CA - R3
	// https://2029.globalsign.com/
	asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 4146, 1, 1},
	// GlobalSign ECC Root CA - R4
	// https://2038r4.globalsign.com
	asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 4146, 1, 1},
	// GlobalSign ECC Root CA - R5
	// https://2038r5.globalsign.com/
	asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 4146, 1, 1},
	// Go Daddy Class 2 Certification Authority
	// https://www.godaddy.com/
	asn1.ObjectIdentifier{2, 16, 840, 1, 114413, 1, 7, 23, 3},
	// Go Daddy Root Certificate Authority - G2
	// https://valid.gdig2.catest.godaddy.com/
	asn1.ObjectIdentifier{2, 16, 840, 1, 114413, 1, 7, 23, 3},
	// GTE CyberTrust Global Root
	// https://www.cybertrust.ne.jp/
	asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 6334, 1, 100, 1},
	// Izenpe.com - SHA256 root
	// The first OID is for businesses and the second for government entities.
	// These are the test sites, respectively:
	// https://servicios.izenpe.com
	// https://servicios1.izenpe.com
	asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 14777, 6, 1, 1},
	asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 14777, 6, 1, 2},
	// Izenpe.com - SHA1 root
	// Windows XP finds this, SHA1, root instead. The policy OIDs are the same
	// as for the SHA256 root, above.
	asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 14777, 6, 1, 1},
	asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 14777, 6, 1, 2},
	// Network Solutions Certificate Authority
	// https://www.networksolutions.com/website-packages/index.jsp
	asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 782, 1, 2, 1, 8, 1},
	// Network Solutions Certificate Authority (reissued certificate with
	// NotBefore of Jan  1 00:00:00 2011 GMT).
	// https://www.networksolutions.com/website-packages/index.jsp
	asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 782, 1, 2, 1, 8, 1},
	// QuoVadis Root CA 2
	// https://www.quovadis.bm/
	asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 8024, 0, 2, 100, 1, 2},
	// QuoVadis Root CA 2 G3
	// https://evsslicag3-v.quovadisglobal.com/
	asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 8024, 0, 2, 100, 1, 2},
	// SecureTrust CA, SecureTrust Corporation
	// https://www.securetrust.com
	// https://www.trustwave.com/
	asn1.ObjectIdentifier{2, 16, 840, 1, 114404, 1, 1, 2, 4, 1},
	// Secure Global CA, SecureTrust Corporation
	asn1.ObjectIdentifier{2, 16, 840, 1, 114404, 1, 1, 2, 4, 1},
	// Security Communication RootCA1
	// https://www.secomtrust.net/contact/form.html
	asn1.ObjectIdentifier{1, 2, 392, 200091, 100, 721, 1},
	// Security Communication EV RootCA1
	// https://www.secomtrust.net/contact/form.html
	asn1.ObjectIdentifier{1, 2, 392, 200091, 100, 721, 1},
	// Security Communication EV RootCA2
	// https://www.secomtrust.net/contact/form.html
	asn1.ObjectIdentifier{1, 2, 392, 200091, 100, 721, 1},
	// Staat der Nederlanden EV Root CA
	// https://pkioevssl-v.quovadisglobal.com/
	asn1.ObjectIdentifier{2, 16, 528, 1, 1003, 1, 2, 7},
	// StartCom Certification Authority
	// https://www.startssl.com/
	asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 23223, 1, 1, 1},
	// Starfield Class 2 Certification Authority
	// https://www.starfieldtech.com/
	asn1.ObjectIdentifier{2, 16, 840, 1, 114414, 1, 7, 23, 3},
	// Starfield Root Certificate Authority - G2
	// https://valid.sfig2.catest.starfieldtech.com/
	asn1.ObjectIdentifier{2, 16, 840, 1, 114414, 1, 7, 23, 3},
	// Starfield Services Root Certificate Authority - G2
	// https://valid.sfsg2.catest.starfieldtech.com/
	asn1.ObjectIdentifier{2, 16, 840, 1, 114414, 1, 7, 24, 3},
	// SwissSign Gold CA - G2
	// https://testevg2.swisssign.net/
	asn1.ObjectIdentifier{2, 16, 756, 1, 89, 1, 2, 1, 1},
	// Swisscom Root EV CA 2
	// https://test-quarz-ev-ca-2.pre.swissdigicert.ch
	asn1.ObjectIdentifier{2, 16, 756, 1, 83, 21, 0},
	// Thawte Premium Server CA
	// https://www.thawte.com/
	asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 7, 48, 1},
	// thawte Primary Root CA
	// https://www.thawte.com/
	asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 7, 48, 1},
	// thawte Primary Root CA - G2
	asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 7, 48, 1},
	// thawte Primary Root CA - G3
	asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 7, 48, 1},
	// TWCA Global Root CA
	// https://evssldemo3.twca.com.tw/index.html
	asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 40869, 1, 1, 22, 3},
	// TWCA Root Certification Authority
	// https://evssldemo.twca.com.tw/index.html
	asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 40869, 1, 1, 22, 3},
	// T-TeleSec GlobalRoot Class 3
	// http://www.telesec.de/ / https://root-class3.test.telesec.de/
	asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 7879, 13, 24, 1},
	// USERTrust ECC Certification Authority
	// https://usertrustecccertificationauthority-ev.comodoca.com/
	asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 6449, 1, 2, 1, 5, 1},
	// USERTrust RSA Certification Authority
	// https://usertrustrsacertificationauthority-ev.comodoca.com/
	asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 6449, 1, 2, 1, 5, 1},
	// UTN-USERFirst-Hardware
	asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 6449, 1, 2, 1, 5, 1},
	// This is the Network Solutions EV OID. However, this root
	// cross-certifies NetSol and so we need it here too.
	asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 782, 1, 2, 1, 8, 1},
	// ValiCert Class 2 Policy Validation Authority
	asn1.ObjectIdentifier{2, 16, 840, 1, 114413, 1, 7, 23, 3},
	asn1.ObjectIdentifier{2, 16, 840, 1, 114414, 1, 7, 23, 3},
	// VeriSign Class 3 Public Primary Certification Authority
	// https://www.verisign.com/
	asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 7, 23, 6},
	// VeriSign Class 3 Public Primary Certification Authority - G4
	asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 7, 23, 6},
	// VeriSign Class 3 Public Primary Certification Authority - G5
	// https://www.verisign.com/
	asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 7, 23, 6},
	// VeriSign Universal Root Certification Authority
	asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 7, 23, 6},
	// Wells Fargo WellsSecure Public Root Certificate Authority
	// https://nerys.wellsfargo.com/test.html
	asn1.ObjectIdentifier{2, 16, 840, 1, 114171, 500, 9},
	// XRamp Global Certification Authority
	asn1.ObjectIdentifier{2, 16, 840, 1, 114404, 1, 1, 2, 4, 1},
	// CN=CFCA EV ROOT,O=China Financial Certification Authority,C=CN
	// https://www.cfca.com.cn/
	asn1.ObjectIdentifier{2, 16, 156, 112554, 3},
	// CN=OISTE WISeKey Global Root GB CA,OU=OISTE Foundation Endorsed,O=WISeKey,C=CH
	// https://www.wisekey.com/repository/cacertificates/
	asn1.ObjectIdentifier{2, 16, 756, 5, 14, 7, 4, 8},
	// CN=TÜRKTRUST Elektronik Sertifika Hizmet Sağlayıcısı H6,O=TÜRKTRUST Bilgi İletişim ve Bilişim Güvenliği Hizmetleri A...,L=Ankara,C=TR
	// https://www.turktrust.com.tr/
	asn1.ObjectIdentifier{2, 16, 792, 3, 0, 3, 1, 1, 5},
}

// CA specific OV OIDs from https://cabforum.org/object-registry/
var OrganizationValidationOIDs = []asn1.ObjectIdentifier{
	// CA/Browser Forum OV OID standard
	// https://cabforum.org/object-registry/
	asn1.ObjectIdentifier{2, 23, 140, 1, 2, 2},
	// CA/Browser Forum individually validated
	asn1.ObjectIdentifier{2, 23, 140, 1, 2, 3},
	// Digicert
	asn1.ObjectIdentifier{2, 16, 840, 1, 114412, 1, 1},
	// D-Trust
	asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 4788, 2, 200, 1},
	// GoDaddy
	asn1.ObjectIdentifier{2, 16, 840, 1, 114413, 1, 7, 23, 2},
	// Logius
	asn1.ObjectIdentifier{2, 16, 528, 1, 1003, 1, 2, 5, 6},
	// QuoVadis
	asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 8024, 0, 2, 100, 1, 1},
	// Starfield
	asn1.ObjectIdentifier{2, 16, 840, 1, 114414, 1, 7, 23, 2},
	// TurkTrust
	asn1.ObjectIdentifier{2, 16, 792, 3, 0, 3, 1, 1, 2},
}

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
			exts.NameConstraints = new(NameConstraints)
			exts.NameConstraints.Critical = c.PermittedDNSDomainsCritical

			exts.NameConstraints.PermittedDNSDomains = c.PermittedDNSDomains
			exts.NameConstraints.PermittedEmailDomains = c.PermittedEmailDomains
			exts.NameConstraints.PermittedIPAddresses = c.PermittedIPAddresses
			exts.NameConstraints.PermittedDirectoryNames = c.PermittedDirectoryNames

			exts.NameConstraints.ExcludedEmailDomains = c.ExcludedEmailDomains
			exts.NameConstraints.ExcludedDNSDomains = c.ExcludedDNSDomains
			exts.NameConstraints.ExcludedIPAddresses = c.ExcludedIPAddresses
			exts.NameConstraints.ExcludedDirectoryNames = c.ExcludedDirectoryNames
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
		} else if e.Id.Equal(oidExtSubjectKeyId) {
			exts.SubjectKeyID = c.SubjectKeyId
		} else if e.Id.Equal(oidExtSignedCertificateTimestampList) {
			exts.SignedCertificateTimestampList = c.SignedCertificateTimestampList
		} else if e.Id.Equal(oidExtensionCTPrecertificatePoison) {
			exts.IsPrecert = true
		} else {
			// Unknown extension
			unk = append(unk, e)
		}
	}
	return exts, unk
}
