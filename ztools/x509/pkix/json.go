// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkix

import (
	"encoding/json"

	"github.com/zmap/zgrab/ztools/zson"
)

type jsonName struct {
	CommonName         zson.StringOrArray
	SerialNumber       zson.StringOrArray
	Country            zson.StringOrArray
	Locality           zson.StringOrArray
	Province           zson.StringOrArray
	StreetAddress      zson.StringOrArray
	Organization       zson.StringOrArray
	OrganizationalUnit zson.StringOrArray
	PostalCode         zson.StringOrArray
	UnknownAttributes  []AttributeTypeAndValue
}

func (jn *jsonName) MarshalJSON() ([]byte, error) {
	enc := make(map[string]interface{})
	if !jn.CommonName.Empty() {
		enc["common_name"] = jn.CommonName
	}
	if !jn.SerialNumber.Empty() {
		enc["serial_number"] = jn.SerialNumber

	}
	if !jn.Country.Empty() {
		enc["country"] = jn.Country
	}
	if !jn.Locality.Empty() {
		enc["locality"] = jn.Locality
	}
	if !jn.Province.Empty() {
		enc["province"] = jn.Province
	}
	if !jn.StreetAddress.Empty() {
		enc["street_address"] = jn.StreetAddress
	}
	if !jn.Organization.Empty() {
		enc["organization"] = jn.Organization
	}
	if !jn.OrganizationalUnit.Empty() {
		enc["organizational_unit"] = jn.OrganizationalUnit
	}
	if !jn.PostalCode.Empty() {
		enc["postal_code"] = jn.PostalCode
	}
	for _, a := range jn.UnknownAttributes {
		enc[a.Type.String()] = a.Value
	}
	return json.Marshal(enc)
}

type jsonAttributeTypeAndValue struct {
	Type  string      `json:"type"`
	Value interface{} `json:"value"`
}

func (a *AttributeTypeAndValue) MarshalJSON() ([]byte, error) {
	var enc jsonAttributeTypeAndValue
	enc.Type = a.Type.String()
	enc.Value = a.Value
	return json.Marshal(&enc)
}

type jsonExtension struct {
	Id       string `json:"id"`
	Critical bool   `json:"critical"`
	Value    []byte `json:"value"`
}

func (e *Extension) MarshalJSON() ([]byte, error) {
	ext := jsonExtension{
		Id:       e.Id.String(),
		Critical: e.Critical,
		Value:    e.Value,
	}
	return json.Marshal(ext)
}

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
