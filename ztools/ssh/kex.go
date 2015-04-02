package ssh

import (
	"crypto/rand"
	"errors"
)

// SSH key exchange types
const (
	KEX_CURVE_25519_SHA256_OPENSSH = "curve25519-sha256@libssh.org"
	KEX_ECDH_SHA2_NISTP256         = "ecdh-sha2-nistp256"
	KEX_ECDH_SHA2_NISTP384         = "ecdh-sha2-nistp384"
	KEX_ECDH_SHA2_NISTP521         = "ecdh-sha2-nistp521"
	KEX_DH_SHA256                  = "diffie-hellman-group-exchange-sha256"
	KEX_DH_SHA1                    = "diffie-hellman-group-exchange-sha1"
	KEX_DH_GROUP14_SHA1            = "diffie-hellman-group14-sha1"
	KEX_DH_GROUP1_SHA1             = "diffie-hellman-group1-sha1"
)

// Host key algorithms
// ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp521-cert-v01@openssh.com,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-ed25519-cert-v01@openssh.com,ssh-rsa-cert-v01@openssh.com,ssh-dss-cert-v01@openssh.com,ssh-rsa-cert-v00@openssh.com,ssh-dss-cert-v00@openssh.com,ssh-ed25519,ssh-rsa,ssh-dss
const (
	HOST_KEY_ECDSA_SHA2_NISTP256_CERT_V01_OPENSSH = "ecdsa-sha2-nistp256-cert-v01@openssh.com"
	HOST_KEY_ECDSA_SHA2_NISTp384_CERT_V01_OPENSSH = "ecdsa-sha2-nistp384-cert-v01@openssh.com"
	HOST_KEY_ECDSA_SHA2_NISTP521_CERT_V01_OPENSSH = "ecdsa-sha2-nistp521-cert-v01@openssh.com"
	HOST_KEY_ECDSA_SHA2_NISTP256                  = "ecdsa-sha2-nistp256"
	HOST_KEY_ECDSA_SHA2_NISTP384                  = "ecdsa-sha2-nistp384"
	HOST_KEY_ECDSA_SHA2_NISTp521                  = "ecdsa-sha2-nistp521"
	HOST_KEY_ED_25519_CERT_V01_OPENSSH            = "ssh-ed25519-cert-v01@openssh.com"
	HOST_KEY_RSA_CERT_V01                         = "ssh-rsa-cert-v01@openssh.com"
	HOST_KEY_DSS_CERT_V01                         = "ssh-dss-cert-v01@openssh.com"
	HOST_KEY_RSA_CERT_V00_OPENSSH                 = "ssh-rsa-cert-v00@openssh.com"
	HOST_KEY_DSS_CERT_V00_OPENSSH                 = "ssh-dss-cert-v00@openssh.com"
	HOST_KEY_ED_25519                             = "ssh-ed25519"
	HOST_KEY_RSA                                  = "ssh-rsa"
	HOST_KEY_DSS                                  = "ssh-dss"
)

// KnownKexAlgorithmNames is an array of all key exchange methods known to this
// package. All key exchange methods are not necessarily implemented.
var KnownKexAlgorithmNames = []string{
	KEX_CURVE_25519_SHA256_OPENSSH,
	KEX_ECDH_SHA2_NISTP256,
	KEX_ECDH_SHA2_NISTP384,
	KEX_ECDH_SHA2_NISTP521,
	KEX_DH_SHA256,
	KEX_DH_SHA1,
	KEX_DH_GROUP14_SHA1,
	KEX_DH_GROUP1_SHA1,
}

var KnownHostKeyAlgorithmNames = []string{
	HOST_KEY_ECDSA_SHA2_NISTP256_CERT_V01_OPENSSH,
	HOST_KEY_ECDSA_SHA2_NISTp384_CERT_V01_OPENSSH,
	HOST_KEY_ECDSA_SHA2_NISTP521_CERT_V01_OPENSSH,
	HOST_KEY_ECDSA_SHA2_NISTP256,
	HOST_KEY_ECDSA_SHA2_NISTP384,
	HOST_KEY_ECDSA_SHA2_NISTp521,
	HOST_KEY_ED_25519_CERT_V01_OPENSSH,
	HOST_KEY_RSA_CERT_V01,
	HOST_KEY_DSS_CERT_V01,
	HOST_KEY_RSA_CERT_V00_OPENSSH,
	HOST_KEY_DSS_CERT_V00_OPENSSH,
	HOST_KEY_ED_25519,
	HOST_KEY_RSA,
	HOST_KEY_DSS,
}

// GenerateKeyExchangeInit generates a KeyExchangeInit message sutiable for
// transmission over the wire based on the configuration passed.
func GenerateKeyExchangeInit(c *Config) (*KeyExchangeInit, error) {
	kxi := new(KeyExchangeInit)
	randReader := c.Random
	if randReader == nil {
		randReader = rand.Reader
	}
	if n, err := randReader.Read(kxi.Cookie[:]); n != len(kxi.Cookie) || err != nil {
		return nil, errors.New("Could not read random source")
	}
	kxi.KexAlgorithms = c.getKexAlgorithms()
	return kxi, nil
}
