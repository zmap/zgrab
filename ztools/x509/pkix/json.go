// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkix

import (
	"encoding/asn1"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
)

func oidFromString(s string, oid *asn1.ObjectIdentifier) (err error) {
	parts := strings.Split(s, ".")
	if len(parts) == 0 {
		*oid = nil
		err = errors.New("invalid OID string")
		return
	}
	*oid = make([]int, len(parts))
	for idx, p := range parts {
		var n int
		if n, err = strconv.Atoi(p); err != nil {
			return
		}
		(*oid)[idx] = n
	}
	return
}

type jsonAttributeTypeAndValue struct {
	Type  string      `json:"type"`
	Value interface{} `json:"value"`
}

// MarshalJSON implements the json.Marshaler interface
func (a *AttributeTypeAndValue) MarshalJSON() ([]byte, error) {
	enc := jsonAttributeTypeAndValue{
		Type:  a.Type.String(),
		Value: a.Value,
	}
	return json.Marshal(&enc)
}

// UnmarshalJSON implements the json.Unmarshaler interface
func (a *AttributeTypeAndValue) UnmarshalJSON(b []byte) error {
	dec := jsonAttributeTypeAndValue{}
	if err := json.Unmarshal(b, &dec); err != nil {
		return err
	}
	if err := oidFromString(dec.Type, &a.Type); err != nil {
		return err
	}
	a.Value = dec.Value
	return nil
}

type jsonExtension struct {
	Id       string `json:"id"`
	Critical bool   `json:"critical"`
	Value    []byte `json:"value"`
}

// MarshalJSON implements the json.Marshaler interface
func (e *Extension) MarshalJSON() ([]byte, error) {
	ext := jsonExtension{
		Id:       e.Id.String(),
		Critical: e.Critical,
		Value:    e.Value,
	}
	return json.Marshal(ext)
}

// UnmarshalJSON implements the json.Unmarshaler interface
func (e *Extension) UnmarshalJSON(b []byte) error {
	dec := jsonExtension{}
	if err := json.Unmarshal(b, &dec); err != nil {
		return err
	}
	if err := oidFromString(dec.Id, &e.Id); err != nil {
		return err
	}
	e.Critical = dec.Critical
	e.Value = dec.Value
	return nil
}

type jsonName struct {
	CommonName         []string `json:"common_name,omitempty"`
	SerialNumber       []string `json:"serial_number,omitempty"`
	Country            []string `json:"country,omitempty"`
	Locality           []string `json:"locality,omitempty"`
	Province           []string `json:"province,omitempty"`
	StreetAddress      []string `json:"street_address,omitempty"`
	Organization       []string `json:"organization,omitempty"`
	OrganizationalUnit []string `json:"organizational_unit,omitempty"`
	PostalCode         []string `json:"postal_code,omitempty"`

	UnknownAttributes []AttributeTypeAndValue `json:"unknown_attributes,omitempty"`
}

// MarshalJSON implements the json.Marshaler interface
func (n *Name) MarshalJSON() ([]byte, error) {
	var enc jsonName
	attrs := n.ToRDNSequence()
	for _, attrSet := range attrs {
		for _, a := range attrSet {
			s, _ := a.Value.(string)
			if a.Type.Equal(oidCommonName) {
				enc.CommonName = append(enc.CommonName, s)
			} else if a.Type.Equal(oidSerialNumber) {
				enc.SerialNumber = append(enc.SerialNumber, s)
			} else if a.Type.Equal(oidCountry) {
				enc.Country = append(enc.Country, s)
			} else if a.Type.Equal(oidLocality) {
				enc.Locality = append(enc.Locality, s)
			} else if a.Type.Equal(oidProvince) {
				enc.Province = append(enc.Province, s)
			} else if a.Type.Equal(oidStreetAddress) {
				enc.StreetAddress = append(enc.StreetAddress, s)
			} else if a.Type.Equal(oidOrganization) {
				enc.Organization = append(enc.Organization, s)
			} else if a.Type.Equal(oidOrganizationalUnit) {
				enc.OrganizationalUnit = append(enc.OrganizationalUnit, s)
			} else if a.Type.Equal(oidPostalCode) {
				enc.PostalCode = append(enc.PostalCode, s)
			} else {
				enc.UnknownAttributes = append(enc.UnknownAttributes, a)
			}
		}
	}
	return json.Marshal(&enc)
}

// UnmarshalJSON implements the json.Unmarshaler interface
func (n *Name) UnmarshalJSON(b []byte) error {
	dec := jsonName{}
	if err := json.Unmarshal(b, &dec); err != nil {
		return err
	}
	if len(dec.CommonName) > 0 {
		n.CommonName = dec.CommonName[0]
	}
	if len(dec.SerialNumber) > 0 {
		n.SerialNumber = dec.SerialNumber[0]
	}
	n.Country = dec.Country
	n.Locality = dec.Locality
	n.Province = dec.Province
	n.StreetAddress = dec.StreetAddress
	n.Organization = dec.Organization
	n.OrganizationalUnit = dec.OrganizationalUnit
	n.PostalCode = dec.PostalCode
	n.ExtraNames = dec.UnknownAttributes
	return nil
}
