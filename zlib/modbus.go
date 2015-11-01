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

package zlib

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strconv"
)

type MEIResponse struct {
	ConformityLevel int          `json:"conformity_level"`
	MoreFollows     bool         `json:"more_follows"`
	ObjectCount     int          `json:"object_count"`
	Objects         MEIObjectSet `json:"objects,omitempty"`
}

type MEIObjectSet []MEIObject

func (ms *MEIObjectSet) MarshalJSON() ([]byte, error) {
	enc := make(map[string]string, len(*ms))
	for _, obj := range *ms {
		enc[obj.OID.Name()] = obj.Value
	}
	return json.Marshal(enc)
}

type MEIObject struct {
	OID   MEIObjectID
	Value string
}

type MEIObjectID int

const (
	OIDVendor              MEIObjectID = 0
	OIDProductCode         MEIObjectID = 1
	OIDRevision            MEIObjectID = 2
	OIDVendorURL           MEIObjectID = 3
	OIDProductName         MEIObjectID = 4
	OIDModelName           MEIObjectID = 5
	OIDUserApplicationName MEIObjectID = 6
)

var meiObjectNames = []string{
	"vendor",
	"product_code",
	"revision",
	"vendor_url",
	"product_name",
	"model_name",
	"user_application_name",
}

func (m *MEIObjectID) Name() string {
	oid := int(*m)
	var name string
	if oid >= len(meiObjectNames) || oid < 0 {
		name = "oid_" + strconv.Itoa(oid)
	} else {
		name = meiObjectNames[oid]
	}
	return name
}

func (m *MEIObject) MarshalJSON() ([]byte, error) {
	enc := make(map[string]interface{}, 1)
	name := m.OID.Name()
	enc[name] = m.Value
	return json.Marshal(enc)
}

type ExceptionResponse struct {
	ExceptionFunction FunctionCode `json:"exception_function"`
	ExceptionType     byte         `json:"exception_type"`
}

type ModbusEvent struct {
	Length           int                `json:"length"`
	UnitID           int                `json:"unit_id"`
	Function         FunctionCode       `json:"function_code"`
	Response         []byte             `json:"raw_response,omitempty"`
	MEIResponse      *MEIResponse       `json:"mei_response,omitempty"`
	ExceptionReponse *ExceptionResponse `json:"exception_response,omitempty"`
}

func (m *ModbusEvent) IsException() bool {
	return (m.Function&0x80 != 0)
}

func (m *ModbusEvent) ParseSelf() {
	if m.IsException() {
		m.parseException()
	} else {
		m.parseReponse()
	}
}

func (m *ModbusEvent) parseException() {
	exceptionFunction := m.Function & 0x7F
	var exceptionType byte
	if len(m.Response) > 0 {
		exceptionType = m.Response[0]
	}
	res := ExceptionResponse{
		ExceptionFunction: exceptionFunction,
		ExceptionType:     exceptionType,
	}
	m.ExceptionReponse = &res
}

func (m *ModbusEvent) parseReponse() {
	if m.Function != FunctionCodeMEI {
		return
	}
	if len(m.Response) < 6 {
		return
	}
	meiType := m.Response[0]
	if meiType != 0x0E {
		return
	}
	readType := m.Response[1]
	if readType != 1 {
		return
	}
	conformityLevel := m.Response[2]
	moreFollows := (m.Response[3] != 0)
	objectCount := m.Response[5]
	objects := make([]MEIObject, objectCount)
	it := 6
	for idx := range objects {
		n, obj := parseMEIObject(m.Response[it:])
		it += n
		if obj == nil {
			break
		}
		objects[idx] = *obj
	}
	res := MEIResponse{
		ConformityLevel: int(conformityLevel),
		MoreFollows:     moreFollows,
		ObjectCount:     int(objectCount),
		Objects:         objects,
	}
	m.MEIResponse = &res
}

func parseMEIObject(objectBytes []byte) (int, *MEIObject) {
	length := len(objectBytes)
	if length < 2 {
		return length, nil
	}
	oid := objectBytes[0]
	objLen := int(objectBytes[1])
	if length < 2+objLen {
		return length, nil
	}
	s := string(objectBytes[2 : 2+objLen])
	obj := MEIObject{
		OID:   MEIObjectID(oid),
		Value: s,
	}
	return 2 + objLen, &obj
}

type FunctionCode byte
type ExceptionFunctionCode byte
type ExceptionCode byte

type ModbusRequest struct {
	Function FunctionCode
	Data     []byte
}

func (r *ModbusRequest) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 7+1+len(r.Data))
	copy(data[0:4], ModbusHeaderBytes)
	msglen := len(r.Data) + 2 // unit ID and function
	binary.BigEndian.PutUint16(data[4:6], uint16(msglen))
	data[6] = 0
	data[7] = byte(r.Function)
	copy(data[8:], r.Data)
	return
}

type ModbusResponse struct {
	Length   int
	UnitID   int
	Function FunctionCode
	Data     []byte
}

func (c *Conn) ReadMin(res []byte, bytes int) (cnt int, err error) {
	for cnt < bytes {
		var n int
		n, err = c.getUnderlyingConn().Read(res[cnt:])
		cnt += n

		if err != nil && cnt >= len(res) {
			err = fmt.Errorf("modbus: response buffer too small")
		}

		if err != nil {
			return
		}
	}

	return
}

func (c *Conn) GetModbusResponse() (res ModbusResponse, err error) {
	var cnt int
	buf := make([]byte, 1024) // should be more memory than we need
	header := buf[0:7]
	buf = buf[7:]

	cnt, err = c.ReadMin(header, 7)
	if err != nil {
		err = fmt.Errorf("modbus: could not get response: %s", err.Error())
		return
	}

	// first 4 bytes should be known, verify them
	if !bytes.Equal(header[0:4], ModbusHeaderBytes) {
		err = fmt.Errorf("modbus: not a modbus response")
		return
	}

	msglen := int(binary.BigEndian.Uint16(header[4:6]))
	unitID := int(header[6])

	cnt = 0
	if msglen > len(buf) {
		msglen = len(buf)
	}
	// One of the bytes in length counts as part of the header
	for cnt < msglen-1 {
		var n int
		n, err = c.getUnderlyingConn().Read(buf[cnt:])
		cnt += n

		if err != nil && cnt >= len(buf) {
			err = fmt.Errorf("modbus: response buffer too small")
		}

		if err != nil {
			break
		}
	}

	if cnt > len(buf) {
		cnt = len(buf)
	}

	var d []byte
	if cnt > 1 {
		d = buf[1:cnt]
	}

	//TODO this really should be done by a more elegant unmarshaling function
	res = ModbusResponse{
		Length:   msglen,
		UnitID:   unitID,
		Function: FunctionCode(buf[0]),
		Data:     d,
	}

	return
}

type ModbusException struct {
	Function      ExceptionFunctionCode
	ExceptionType ExceptionCode
}

func (e ExceptionFunctionCode) FunctionCode() FunctionCode {
	code := byte(e) & byte(0x79)
	return FunctionCode(code)
}

func (c FunctionCode) ExceptionFunctionCode() ExceptionFunctionCode {
	code := byte(c) | byte(0x80)
	return ExceptionFunctionCode(code)
}

func (c FunctionCode) IsException() bool {
	return (byte(c) & 0x80) == 0x80
}

var ModbusHeaderBytes = []byte{
	0x13, 0x37, // do not matter, will just be verifying they are the same
	0x00, 0x00, // must be 0
}

var ModbusFunctionEncapsulatedInterface = FunctionCode(0x2B)

const (
	FunctionCodeMEI = FunctionCode(0x2B)
)
