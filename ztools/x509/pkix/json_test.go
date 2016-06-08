// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkix

import (
	"encoding/asn1"
	"reflect"
	"testing"
)

func TestAttributeTypeAndValueJSON(t *testing.T) {
	var atvs = []AttributeTypeAndValue{
		{Type: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: "some string"},
		{Type: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: 8.0},
		{Type: asn1.ObjectIdentifier{0, 0, 3, 4, 5, 2018, 0, 1, 0}, Value: "another string"},
	}
	for idx, atv := range atvs {
		b, errMarshal := atv.MarshalJSON()
		if errMarshal != nil {
			t.Errorf("unabled to marshal %v (index %d)", atv, idx)
			continue
		}
		dec := AttributeTypeAndValue{}
		errUnmarshal := dec.UnmarshalJSON(b)
		if errUnmarshal != nil {
			t.Errorf("unable to unmarshal %b to %v, (index %d)", b, atv, idx)
			continue
		}
		if !dec.Type.Equal(atv.Type) {
			t.Errorf("mismatched OID's: got %v, wanted %v", dec.Type, atv.Type)
			continue
		}
		originalValueType := reflect.TypeOf(atv.Value)
		decodedValueType := reflect.TypeOf(dec.Value)
		if originalValueType != decodedValueType {
			t.Errorf("mismatched types for Value: got %v, wanted %v", decodedValueType, originalValueType)
		}
		if !reflect.DeepEqual(dec.Value, atv.Value) {
			t.Errorf("mismatched values: got %v, wanted %v", dec.Value, atv.Value)
		}
	}
}

func TestExtensionJSON(t *testing.T) {
	var exts = []Extension{
		{Id: asn1.ObjectIdentifier{1, 0, 2018, 65888}, Critical: true, Value: []byte{6, 6, 255, 0}},
		{Id: asn1.ObjectIdentifier{1, 0, 2018, 65888}, Critical: false, Value: []byte{6, 6, 255, 0}},
	}
	for idx, e := range exts {
		b, errMarshal := e.MarshalJSON()
		if errMarshal != nil {
			t.Errorf("unable to marshal %v (index %d)", e, idx)
			continue
		}
		var dec Extension
		errUnmarshal := dec.UnmarshalJSON(b)
		if errUnmarshal != nil {
			t.Errorf("unabled to unmarshal %v (index %d, byte %b)", e, idx, b)
			continue
		}
		if !reflect.DeepEqual(dec, e) {
			t.Errorf("mistmached values: got %v, wanted %v", dec, e)
		}
	}
}

func TestNameJSON(t *testing.T) {
	var names = []Name{
		{},
		{
			CommonName:   "davidadrian.org",
			SerialNumber: "1543402260525779",
			Country:      []string{"US"},
			Organization: []string{"who", "really", "cares"},
			ExtraNames: []AttributeTypeAndValue{
				{
					Type:  asn1.ObjectIdentifier{0, 7, 3, 4},
					Value: "value",
				},
			},
		},
	}
	for idx, n := range names {
		b, errMarshal := n.MarshalJSON()
		if errMarshal != nil {
			t.Errorf("unable to marshal %v (index %d)", n, idx)
			continue
		}
		var dec Name
		errUnmarshal := dec.UnmarshalJSON(b)
		if errUnmarshal != nil {
			t.Errorf("unabled to unmarshal %v (index %d, byte %b)", n, idx, b)
			continue
		}
		if !reflect.DeepEqual(dec, n) {
			t.Errorf("mistmached values: got %v, wanted %v", dec, n)
		}
	}
}
