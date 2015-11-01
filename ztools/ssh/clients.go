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

type ClientImplementation struct {
	kexAlgorithms        []string
	hostKeyAlgorithms    []string
	encryptionAlgorithms []string
	macAlgorithms        []string
	minDHGroupSize       uint32
	preferredDHGroupSize uint32
	maxDHGroupSize       uint32
}

var clientImplementations = make(map[string]*ClientImplementation)

func (c *ClientImplementation) KexAlgorithms() NameList {
	return c.kexAlgorithms
}

func (c *ClientImplementation) HostKeyAlgorithms() NameList {
	return c.hostKeyAlgorithms
}

func ClientImplementationByName(name string) (c *ClientImplementation, ok bool) {
	c, ok = clientImplementations[name]
	return
}

var OpenSSH_6_6p1 = ClientImplementation{
	kexAlgorithms: []string{
		KEX_CURVE_25519_SHA256_OPENSSH,
		KEX_ECDH_SHA2_NISTP256,
		KEX_ECDH_SHA2_NISTP384,
		KEX_ECDH_SHA2_NISTP521,
		KEX_DH_SHA256,
		KEX_DH_SHA1,
		KEX_DH_GROUP14_SHA1,
		KEX_DH_GROUP1_SHA1,
	},
	hostKeyAlgorithms: []string{
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
	},
	minDHGroupSize:       1024,
	preferredDHGroupSize: 3072,
	maxDHGroupSize:       8072,
}

var dropbear_0_46 = ClientImplementation{
	kexAlgorithms: []string{
		KEX_DH_GROUP1_SHA1,
	},
	hostKeyAlgorithms: []string{
		HOST_KEY_RSA,
		HOST_KEY_DSS,
	},
	encryptionAlgorithms: []string{
		ENCRYPTION_3DES_CBC,
	},
	macAlgorithms: []string{
		MAC_HMAC_SHA1,
		MAC_HMAC_MD5,
	},
}

func init() {
	clientImplementations["OpenSSH_6.6p1"] = &OpenSSH_6_6p1
}
