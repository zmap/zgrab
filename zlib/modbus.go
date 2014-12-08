package zlib

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
)

type ModbusEvent struct {
	Length   int
	UnitID   int
	Function FunctionCode
	Response []byte
}

var ModbusEventType = EventType{
	TypeName:         CONNECTION_EVENT_MODBUS,
	GetEmptyInstance: func() EventData { return new(ModbusEvent) },
}

func (m *ModbusEvent) GetType() EventType {
	return ModbusEventType
}

type encodedModbusEvent struct {
	Length   int          `json:"length"`
	UnitID   int          `json:"unit_id"`
	Function FunctionCode `json:"function_code"`
	Response []byte       `json:"response"`
}

func (m *ModbusEvent) MarshalJSON() ([]byte, error) {
	e := encodedModbusEvent{
		Length:   m.Length,
		UnitID:   m.UnitID,
		Function: m.Function,
		Response: m.Response,
	}
	return json.Marshal(&e)
}

func (m *ModbusEvent) UnmarshalJSON(b []byte) error {
	e := new(encodedModbusEvent)
	if err := json.Unmarshal(b, e); err != nil {
		return err
	}
	m.Length = e.Length
	m.Function = e.Function
	m.Response = e.Response
	return nil
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
