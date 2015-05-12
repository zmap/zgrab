package x509

var signatureAlgorithmNames = []string{
	"unknown_algorithm",
	"MD2WithRSA",
	"MD5WithRSA",
	"SHA1WithRSA",
	"SHA256WithRSA",
	"SHA384WithRSA",
	"SHA512WithRSA",
	"DSAWithSHA1",
	"DSAWithSHA256",
	"ECDSAWithSHA1",
	"ECDSAWithSHA256",
	"ECDSAWitHSHA384",
	"ECDSAWithSHA512",
}

var keyAlgorithmNames = []string{
	"unknown_algorithm",
	"RSA",
	"DSA",
	"ECDSA",
}

func (s SignatureAlgorithm) String() string {
	if s >= total_signature_algorithms || s < 0 {
		s = UnknownSignatureAlgorithm
	}
	return signatureAlgorithmNames[s]
}

func (p PublicKeyAlgorithm) String() string {
	if p >= total_key_algorithms || p < 0 {
		p = UnknownPublicKeyAlgorithm
	}
	return keyAlgorithmNames[p]
}

func (c *Certificate) SignatureAlgorithmName() string {
	switch c.SignatureAlgorithm {
	case UnknownSignatureAlgorithm:
		return c.SignatureAlgorithmOID.String()
	default:
		return c.SignatureAlgorithm.String()
	}
}

func (c *Certificate) PublicKeyAlgorithmName() string {
	switch c.PublicKeyAlgorithm {
	case UnknownPublicKeyAlgorithm:
		return c.PublicKeyAlgorithmOID.String()
	default:
		return c.PublicKeyAlgorithm.String()
	}
}
