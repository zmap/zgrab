// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ztls

import (
	"encoding/json"
	"reflect"
	"testing"
)

type ZTLSHandshakeSuite struct{}

func marshalAndUnmarshal(original interface{}, target interface{}) error {
	var b []byte
	var err error
	if b, err = json.Marshal(original); err != nil {
		return err
	}
	if err = json.Unmarshal(b, target); err != nil {
		return err
	}
	return nil
}

func marshalAndUnmarshalAndCheckEquality(original interface{}, target interface{}, t *testing.T) {
	if err := marshalAndUnmarshal(original, target); err != nil {
		t.Fatalf("unable to marshalAndUnmarshal: %s", err.Error())
	}
	if eq := reflect.DeepEqual(original, target); eq != true {
		t.Errorf("expected %+v to equal %+v", original, target)
	}
}

func TestTLSVersionEncodeDecode(t *testing.T) {
	v := TLSVersion(VersionTLS12)
	var dec TLSVersion
	marshalAndUnmarshalAndCheckEquality(&v, &dec, t)
}

func TestCipherSuiteEncodeDecode(t *testing.T) {
	v := CipherSuite(TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256)
	var dec CipherSuite
	marshalAndUnmarshalAndCheckEquality(&v, &dec, t)
	expectedName := nameForSuite(TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256)
	if decodedName := dec.String(); decodedName != expectedName {
		t.Errorf("decoded wrong name, got %s, expected %s", decodedName, expectedName)
	}
}
