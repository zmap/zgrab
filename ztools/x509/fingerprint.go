// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
)

type CertificateFingerprint []byte

func MD5Fingerprint(data []byte) CertificateFingerprint {
	sum := md5.Sum(data)
	return sum[:]
}

func SHA1Fingerprint(data []byte) CertificateFingerprint {
	sum := sha1.Sum(data)
	return sum[:]
}

func SHA256Fingerprint(data []byte) CertificateFingerprint {
	sum := sha256.Sum256(data)
	return sum[:]
}

func SHA512Fingerprint(data []byte) CertificateFingerprint {
	sum := sha512.Sum512(data)
	return sum[:]
}

func (f *CertificateFingerprint) Hex() string {
	return hex.EncodeToString(*f)
}

func (f *CertificateFingerprint) MarshalJSON() ([]byte, error) {
	return json.Marshal(f.Hex())
}
