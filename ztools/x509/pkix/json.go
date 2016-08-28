// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkix

import (
	"encoding/asn1"
	"encoding/json"
	"fmt"
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
	DomainComponent    []string //technically deprecated, but yolo
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

func convertToStrArray(i interface{}) []string {

	var strArray []string

	arr, _ := i.([]interface{})
	for _, val := range arr {
		if str, ok := val.(string); ok {
			strArray = append(strArray, str)
		}
	}

	return strArray
}

func (jn *jsonName) UnmarshalJSON(b []byte) error {
	nameMap := make(map[string]interface{})

	if err := json.Unmarshal(b, &nameMap); err != nil {
		return err
	}

	for key, val := range nameMap {
		switch key {
		case "common_name":
			jn.CommonName = convertToStrArray(val)
		case "serial_number":
			jn.SerialNumber = convertToStrArray(val)
		case "country":
			jn.Country = convertToStrArray(val)
		case "locality":
			jn.Locality = convertToStrArray(val)
		case "province":
			jn.Province = convertToStrArray(val)
		case "street_address":
			jn.StreetAddress = convertToStrArray(val)
		case "organization":
			jn.Organization = convertToStrArray(val)
		case "organizational_unit":
			jn.OrganizationalUnit = convertToStrArray(val)
		case "postal_code":
			jn.PostalCode = convertToStrArray(val)
		case "domain_component":
			jn.DomainComponent = convertToStrArray(val)
		default:
			attributeType := asn1.ObjectIdentifier{}
			valStr, okStr := val.(string)
			if !okStr {
				return fmt.Errorf("Expected string value for field %s, got %T", key, val)
			}

			for _, oidString := range strings.Split(valStr, ".") {
				oidInt, err := strconv.Atoi(oidString)
				if err != nil {
					return err
				}
				attributeType = append(attributeType, oidInt)
			}

			atv := AttributeTypeAndValue{
				Type:  attributeType,
				Value: val,
			}

			jn.UnknownAttributes = append(jn.UnknownAttributes, atv)
		}

	}

	return nil
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

const (
	asn1ClassUniversal       = 0
	asn1ClassApplication     = 1
	asn1ClassContextSpecific = 2
	asn1ClassPrivate         = 3
)

func (o *OtherName) UnmarshalJSON(b []byte) (err error) {
	var oName jsonOtherName

	if err = json.Unmarshal(b, &oName); err != nil {
		return
	}

	arcs := strings.Split(oName.Id, ".")
	oid := make(asn1.ObjectIdentifier, len(arcs))

	for i, s := range arcs {
		var tmp int64
		tmp, err = strconv.ParseInt(s, 10, 32)
		if err != nil {
			return
		}
		oid[i] = int(tmp)
	}
	o.Typeid = oid

	o.Value = asn1.RawValue{
		Tag: 0,
		//TODO: change to asn1.ClassContextSpecific for next major release (i.e. 1.6)
		Class:      asn1ClassContextSpecific,
		IsCompound: true,
		Bytes:      oName.Value,
	}
	o.Value.FullBytes, err = asn1.Marshal(o.Value)
	return
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

func appendATV(names []AttributeTypeAndValue, fieldVals []string, asn1Id asn1.ObjectIdentifier) []AttributeTypeAndValue {
	if len(fieldVals) == 0 {
		return names
	}

	for _, val := range fieldVals {
		names = append(names, AttributeTypeAndValue{Type: asn1Id, Value: val})
	}

	return names
}

func (n *Name) UnmarshalJSON(b []byte) error {
	var jName jsonName

	if err := jName.UnmarshalJSON(b); err != nil {
		return err
	}

	// add everything to names
	n.Names = appendATV(n.Names, jName.Country, oidCountry)
	n.Names = appendATV(n.Names, jName.Organization, oidOrganization)
	n.Names = appendATV(n.Names, jName.OrganizationalUnit, oidOrganizationalUnit)
	n.Names = appendATV(n.Names, jName.Locality, oidLocality)
	n.Names = appendATV(n.Names, jName.Province, oidProvince)
	n.Names = appendATV(n.Names, jName.StreetAddress, oidStreetAddress)
	n.Names = appendATV(n.Names, jName.PostalCode, oidPostalCode)
	n.Names = appendATV(n.Names, jName.DomainComponent, oidDomainComponent)

	// populate specific fields
	n.Country = jName.Country
	n.Organization = jName.Organization
	n.OrganizationalUnit = jName.OrganizationalUnit
	n.Locality = jName.Locality
	n.Province = jName.Province
	n.StreetAddress = jName.StreetAddress
	n.PostalCode = jName.PostalCode
	n.DomainComponent = jName.DomainComponent

	// add first commonNames and serialNumbers to struct and Names
	if len(jName.CommonName) > 0 {
		n.CommonName = jName.CommonName[0]
		n.Names = append(n.Names, AttributeTypeAndValue{Type: oidCommonName, Value: jName.CommonName[0]})
	}
	if len(jName.SerialNumber) > 0 {
		n.SerialNumber = jName.SerialNumber[0]
		n.Names = append(n.Names, AttributeTypeAndValue{Type: oidSerialNumber, Value: jName.SerialNumber[0]})
	}

	// add extra commonNames and serialNumbers to extraNames
	if len(jName.CommonName) > 1 {
		for _, val := range jName.CommonName[1:] {
			n.ExtraNames = append(n.ExtraNames, AttributeTypeAndValue{Type: oidCommonName, Value: val})
		}
	}

	if len(jName.SerialNumber) > 1 {
		for _, val := range jName.SerialNumber[1:] {
			n.ExtraNames = append(n.ExtraNames, AttributeTypeAndValue{Type: oidSerialNumber, Value: val})
		}
	}

	return nil
}
