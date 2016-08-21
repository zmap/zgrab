// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkix

import (
	"encoding/asn1"
	"encoding/json"
	"strconv"
	"strings"
)

type jsonName struct {
	CommonName         []string
	SerialNumber       []string
	Country            []string
	Locality           []string
	Province           []string
	StreetAddress      []string
	Organization       []string
	OrganizationalUnit []string
	PostalCode         []string
	DomainComponent    []string //technically depricated, but yolo
	UnknownAttributes  []AttributeTypeAndValue
}

func (jn *jsonName) MarshalJSON() ([]byte, error) {
	enc := make(map[string]interface{})
	if len(jn.CommonName) > 0 {
		enc["common_name"] = jn.CommonName
	}
	if len(jn.SerialNumber) > 0 {
		enc["serial_number"] = jn.SerialNumber
	}
	if len(jn.Country) > 0 {
		enc["country"] = jn.Country
	}
	if len(jn.Locality) > 0 {
		enc["locality"] = jn.Locality
	}
	if len(jn.Province) > 0 {
		enc["province"] = jn.Province
	}
	if len(jn.StreetAddress) > 0 {
		enc["street_address"] = jn.StreetAddress
	}
	if len(jn.Organization) > 0 {
		enc["organization"] = jn.Organization
	}
	if len(jn.OrganizationalUnit) > 0 {
		enc["organizational_unit"] = jn.OrganizationalUnit
	}
	if len(jn.PostalCode) > 0 {
		enc["postal_code"] = jn.PostalCode
	}
	if len(jn.DomainComponent) > 0 {
		enc["domain_component"] = jn.DomainComponent
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

type jsonOtherName struct {
	Id    string `json:"id"`
	Value []byte `json:"value"`
}

func (o *OtherName) MarshalJSON() ([]byte, error) {
	oName := jsonOtherName{
		Id:    o.Typeid.String(),
		Value: o.Value.Bytes,
	}
	return json.Marshal(oName)
}

func (o *OtherName) UnmarshalJSON(b []byte) error {
	var oName jsonOtherName

	if err := json.Unmarshal(b, &oName); err != nil {
		return err
	}

	arcs := strings.Split(oName.Id, ".")
	oid := make(asn1.ObjectIdentifier, len(arcs))

	for i, s := range arcs {
		tmp, err := strconv.ParseInt(s, 10, 32)
		if err != nil {
			return err
		}
		oid[i] = int(tmp)
	}
	o.Typeid = oid

	o.Value = asn1.RawValue{
		Tag:        0,
		Class:      asn1.ClassContextSpecific,
		IsCompound: true,
		Bytes:      oName.Value,
	}
	return nil
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
			} else if a.Type.Equal(oidDomainComponent) {
				enc.DomainComponent = append(enc.DomainComponent, s)
			} else {
				enc.UnknownAttributes = append(enc.UnknownAttributes, a)
			}
		}
	}
	return json.Marshal(&enc)
}
