/*
 * ZGrab Copyright 2015 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

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
	HOST_KEY_ECDSA_SHA2_NISTP384_CERT_V01_OPENSSH = "ecdsa-sha2-nistp384-cert-v01@openssh.com"
	HOST_KEY_ECDSA_SHA2_NISTP521_CERT_V01_OPENSSH = "ecdsa-sha2-nistp521-cert-v01@openssh.com"
	HOST_KEY_ECDSA_SHA2_NISTP256                  = "ecdsa-sha2-nistp256"
	HOST_KEY_ECDSA_SHA2_NISTP384                  = "ecdsa-sha2-nistp384"
	HOST_KEY_ECDSA_SHA2_NISTP521                  = "ecdsa-sha2-nistp521"
	HOST_KEY_ED_25519_CERT_V01_OPENSSH            = "ssh-ed25519-cert-v01@openssh.com"
	HOST_KEY_RSA_CERT_V01                         = "ssh-rsa-cert-v01@openssh.com"
	HOST_KEY_DSS_CERT_V01                         = "ssh-dss-cert-v01@openssh.com"
	HOST_KEY_RSA_CERT_V00_OPENSSH                 = "ssh-rsa-cert-v00@openssh.com"
	HOST_KEY_DSS_CERT_V00_OPENSSH                 = "ssh-dss-cert-v00@openssh.com"
	HOST_KEY_ED_25519                             = "ssh-ed25519"
	HOST_KEY_RSA                                  = "ssh-rsa"
	HOST_KEY_DSS                                  = "ssh-dss"
)

// Encryption types
const (
	ENCRYPTION_AES_128_CTR                 = "aes128-ctr"
	ENCRYPTION_AES_192_CTR                 = "aes192-ctr"
	ENCRYPTION_AES_256_CTR                 = "aes256-ctr"
	ENCRPTION_ARCFOUR_256                  = "arcfour256"
	ENCRYPTION_ARCFOUR_128                 = "arcfour128"
	ENCRYPTION_AES_128_GCM_OPENSSH         = "aes128-gcm@openssh.com"
	ENCRYPTION_AES_256_GCM_OPENSSH         = "aes256-gcm@openssh.com"
	ENCRYPTION_CHACHA_20_POLY_1305_OPENSSH = "chacha20-poly1305@openssh.com"
	ENCRYPTION_AES_128_CBC                 = "aes128-cbc"
	ENCRYPTION_3DES_CBC                    = "3des-cbc"
	ENCRYPTION_BLOWFISH_CBC                = "blowfish-cbc"
	ENCRYPTION_CAST_128_CBC                = "cast128-cbc"
	ENCRYPTION_AES_192_CBC                 = "aes192-cbc"
	ENCRYPTION_AES_256_CBC                 = "aes256-cbc"
	ENCRYPTION_ARCFOUR                     = "arcfour"
	ENCRYPTION_RIJNDAEL_CBC_LYSATOR        = "rijndael-cbc@lysator.liu.se"
)

// MAC types
const (
	MAC_HMAC_MD5_ETM_OPENSSH        = "hmac-md5-etm@openssh.com"
	MAC_HMAC_SHA1_ETM_OPENSSH       = "hmac-sha1-etm@openssh.com"
	MAC_UMAC_64_ETM_OPENSSH         = "umac-64-etm@openssh.com"
	MAC_UMAC_128_ETM_OPENSSH        = "umac-128-etm@openssh.com"
	MAC_HMAC_SHA2_256_ETM_OPENSSH   = "hmac-sha2-256-etm@openssh.com"
	MAC_HMAC_SHA2_512_ETM_OPENSSH   = "hmac-sha2-512-etm@openssh.com"
	MAC_HMAC_RIPEMD_160_ETM_OPENSSH = "hmac-ripemd160-etm@openssh.com"
	MAC_HMAC_SHA1_96_ETM_OPENSSH    = "hmac-sha1-96-etm@openssh.com"
	MAC_HMAC_MD5_96_ETM             = "hmac-md5-96-etm@openssh.com"
	MAC_HMAC_MD5                    = "hmac-md5"
	MAC_HMAC_SHA1                   = "hmac-sha1"
	MAC_UMAC_64_OPENSSH             = "umac-64@openssh.com"
	MAC_UMAC_128_OPENSSH            = "umac-128@openssh.com"
	MAC_HMAC_SHA2_256               = "hmac-sha2-256"
	MAC_HMAC_SHA2_512               = "hmac-sha2-512"
	MAC_HMAC_RIPEMD_160             = "hmac-ripemd160"
	MAC_HMAC_RIPEMD_160_OPENSSH     = "hmac-ripemd160@openssh.com"
	MAC_HMAC_SHA1_96                = "hmac-sha1-96"
	MAC_HMAC_MD5_96                 = "hmac-md5-96"
)

// Compression types
const (
	COMPRESSION_NONE         = "none"
	COMPRESSION_ZLIB_OPENSSH = "zlib@openssh.com"
	COMPRESSION_ZLIB         = "zlib"
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
	HOST_KEY_ECDSA_SHA2_NISTP384_CERT_V01_OPENSSH,
	HOST_KEY_ECDSA_SHA2_NISTP521_CERT_V01_OPENSSH,
	HOST_KEY_ECDSA_SHA2_NISTP256,
	HOST_KEY_ECDSA_SHA2_NISTP384,
	HOST_KEY_ECDSA_SHA2_NISTP521,
	HOST_KEY_ED_25519_CERT_V01_OPENSSH,
	HOST_KEY_RSA_CERT_V01,
	HOST_KEY_DSS_CERT_V01,
	HOST_KEY_RSA_CERT_V00_OPENSSH,
	HOST_KEY_DSS_CERT_V00_OPENSSH,
	HOST_KEY_ED_25519,
	HOST_KEY_RSA,
	HOST_KEY_DSS,
}

var KnownEncryptionAlgorithmNames = []string{
	ENCRYPTION_AES_128_CTR,
	ENCRYPTION_AES_192_CTR,
	ENCRYPTION_AES_256_CTR,
	ENCRPTION_ARCFOUR_256,
	ENCRYPTION_ARCFOUR_128,
	ENCRYPTION_AES_128_GCM_OPENSSH,
	ENCRYPTION_AES_256_GCM_OPENSSH,
	ENCRYPTION_CHACHA_20_POLY_1305_OPENSSH,
	ENCRYPTION_AES_128_CBC,
	ENCRYPTION_3DES_CBC,
	ENCRYPTION_BLOWFISH_CBC,
	ENCRYPTION_CAST_128_CBC,
	ENCRYPTION_AES_192_CBC,
	ENCRYPTION_AES_256_CBC,
	ENCRYPTION_ARCFOUR,
	ENCRYPTION_RIJNDAEL_CBC_LYSATOR,
}

var KnownMACAlgorithmNames = []string{
	MAC_HMAC_MD5_ETM_OPENSSH,
	MAC_HMAC_SHA1_ETM_OPENSSH,
	MAC_UMAC_64_ETM_OPENSSH,
	MAC_UMAC_128_ETM_OPENSSH,
	MAC_HMAC_SHA2_256_ETM_OPENSSH,
	MAC_HMAC_SHA2_512_ETM_OPENSSH,
	MAC_HMAC_RIPEMD_160_ETM_OPENSSH,
	MAC_HMAC_SHA1_96_ETM_OPENSSH,
	MAC_HMAC_MD5_96_ETM,
	MAC_HMAC_MD5,
	MAC_HMAC_SHA1,
	MAC_UMAC_64_OPENSSH,
	MAC_UMAC_128_OPENSSH,
	MAC_HMAC_SHA2_256,
	MAC_HMAC_SHA2_512,
	MAC_HMAC_RIPEMD_160,
	MAC_HMAC_RIPEMD_160_OPENSSH,
	MAC_HMAC_SHA1_96,
	MAC_HMAC_MD5_96,
}

var KnownCompressionAlgorithmNames = []string{
	COMPRESSION_NONE,
	COMPRESSION_ZLIB_OPENSSH,
	COMPRESSION_ZLIB,
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
	kxi.HostKeyAlgorithms = c.getHostKeyAlgorithms()
	kxi.EncryptionClientToServer = c.getClientEncryption()
	kxi.EncryptionServerToClient = c.getServerEncryption()
	kxi.MACClientToServer = c.getClientMAC()
	kxi.MACServerToClient = c.getServerMAC()
	kxi.CompressionClientToServer = c.getClientCompression()
	kxi.CompressionServerToClient = c.getServerCompression()
	kxi.LanguageClientToServer = make([]string, 0)
	kxi.LanguageServerToClient = make([]string, 0)
	return kxi, nil
}

func chooseAlgorithm(clientAlgorithms, serverAlgorithms NameList) (string, error) {
	for clientIdx := range clientAlgorithms {
		for serverIdx := range serverAlgorithms {
			if serverAlgorithms[serverIdx] == clientAlgorithms[clientIdx] {
				return clientAlgorithms[clientIdx], nil
			}
		}
	}
	return "", errors.New("Could not agree on algorithm")
}
