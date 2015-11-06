package iscsi

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	//	"net"
)

const (
	// Initiator opcodes
	NOP_OUT               byte = 0
	ISCSI_COMMAND         byte = 1
	ISCSI_TASK_MANAGEMENT byte = 2
	LOGIN_REQUEST         byte = 3
	TEXT_REQUEST          byte = 4
	SCSI_DATA_OUT         byte = 5
	LOGOUT_REQUEST        byte = 6
	SNACK_REQUEST         byte = 0x10

	// Target opcodes
	NOP_IN               byte = 0x20
	SCSI_RESPONSE        byte = 0x21
	SCSI_TASK_MANAGEMENT byte = 0x22
	LOGIN_RESPONSE       byte = 0x23
	TEXT_RESPONSE        byte = 0x24
	SCSI_DATA_IN         byte = 0x25
	LOGOUT_RESPONSE      byte = 0x26
	READY_TO_TRANSFER    byte = 0x31
	ASYNCHRONOUS_MESSAGE byte = 0x32
	REJECT               byte = 0x3f

	// Special Bits, which need to be added to certain opcodes or fields
	REQUEST_PDU byte = 0x40 // added to opcode denotes request
	FINAL       byte = 0x80 // added to first field denotes final (or only) PDU
	TRANSIT     byte = 0x80 // added to first field denotes readiness to transit to next stage
	CONTINUE    byte = 0x40 // added to first field denotes that request is incomplete

	NSG_SECURITY byte = 0x00
	NSG_LOGIN    byte = 0x01
	NSG_FULL     byte = 0x03

	CSG_SECURITY byte = 0x00
	CSG_LOGIN    byte = 0x04
	CSG_FULL     byte = 0xc

	ISID_OUI      = 0x00
	ISID_EN       = 0x40
	ISID_RANDOM   = 0x80
	ISID_RESERVED = 0xc0

	// AHSTypes
	EXTENDED_CBD                            byte = 0x01
	EXPECTED_BIDIRECTIONAL_READ_DATA_LENGTH byte = 0x02

	VERSION_MAX byte = 0
	VERSION_MIN byte = 0
)

var (
	// Cisco OUI as per IEEE
	ISID_CISCO_OUI [6]byte = [6]byte{0, 0x02, 0x3d, 0, 0, 0}
	TSIH_LOGIN     [2]byte = [2]byte{0, 0}
)

type Header interface {
	// empty for now
}

type BasicHeader struct {
	Opcode            byte
	Flags             byte
	VersionMax        byte
	VersionMin        byte
	TotalAHSLength    byte
	DataSegmentLength [3]byte
}

type TextParameter struct {
	Key   string
	Value string
}

func (t *TextParameter) GetLength() {

}

type Parameters struct {
	Data []TextParameter
	L    int
}

func (p *Parameters) AddTextParameter(key, value string) {
	p.Data = append(p.Data, TextParameter{key, value})
	p.L += len(key) + len(value) + 2
	//p.Header.SetLength(p.l)
}

func (p *Parameters) Length() [3]byte {
	length := []byte{}
	res := [3]byte{}
	fmt.Sscanf(fmt.Sprintf("%06x", p.L), "%x", &length)
	copy(res[:], length)
	return res
}

func (p *Parameters) Print() {
	for _, param := range p.Data {
		fmt.Printf("%s: %s\n", param.Key, param.Value)
	}
}

type PDU struct {
	Header Header
	Data   Parameters
}

func (p PDU) MarshalBinary() ([]byte, error) {
	buf := new(bytes.Buffer)
	//copy(p.Header.GetLength(), length)
	//p.Header.GetLength()
	err := binary.Write(buf, binary.BigEndian, p.Header)
	if err != nil {
		return buf.Bytes(), err
	}
	for _, param := range p.Data.Data {
		_, err = buf.Write([]byte(param.Key + "=" + param.Value + "\u0000"))
		if err != nil {
			return buf.Bytes(), err
		}
	}

	for i := 0; i < p.Data.L%4; i++ {
		buf.Write([]byte{0})
	}

	return buf.Bytes(), err

}

func (p *PDU) UnmarshalBinary(data []byte) error {
	//	fmt.Printf("%x\n", data)
	buf := bytes.NewBuffer(data)
	err := binary.Read(buf, binary.BigEndian, p.Header)
	if err != nil {
		return err
	}
	for {
		line, err := buf.ReadString(0x00)
		if err != nil {
			return err
		}
		entry := strings.Split(strings.TrimSuffix(line, "\u0000"), "=")
		if len(entry) == 2 {
			p.Data.AddTextParameter(entry[0], entry[1])
		}
	}
	//fmt.Print(buf)
	//	buf2 := bytes.NewBuffer(p.Data)
	//	_, err = buf2.ReadFrom(buf)
	//	p.Data = buf2.Bytes()
	return err
}

func NewPDU(header Header, parameters Parameters) PDU {
	return PDU{header, parameters}

}

type LoginHeader struct {
	BasicHeader
	ISID             [6]byte
	TISH             [2]byte
	InitiatorTaskTag [4]byte
}

type LoginRequestHeader struct {
	LoginHeader
	CID      [4]byte // actually 2 + 2 reserved bytes
	CmdSN    [4]byte
	Reserved [20]byte
}

type LoginResponseHeader struct {
	LoginHeader
	Reserved1    [4]byte
	StatSN       [4]byte
	ExpCmdSN     [4]byte
	MaxCmdSN     [4]byte
	StatusClass  byte
	StatusDetail byte
	Reserved2    [10]byte
}

type TextResponseHeader struct {
	BasicHeader
	Reserved1         [8]byte
	InitiatorTaskTag  [4]byte
	TargetTransferTag [4]byte
	StatSN            [4]byte
	ExpCmdSN          [4]byte
	MaxCmdSN          [4]byte
	Reserved2         [8]byte
}

type TextRequestHeader struct {
	BasicHeader
	Reserved1         [8]byte
	InitiatorTaskTag  [4]byte
	TargetTransferTag [4]byte
	CmdSN             [4]byte
	ExpStatSN         [4]byte
	Reserved2         [16]byte
}

type TextResponse struct {
	PDU
}

func NewTextResponse() TextResponse {
	return TextResponse{PDU{new(TextResponseHeader), Parameters{}}}
}

type TextRequest struct {
	PDU
}

func NewTextRequest(parameters Parameters, CmdSN, ExpStatSN [4]byte) TextRequest {
	return TextRequest{NewPDU(
		TextRequestHeader{
			BasicHeader{
				TEXT_REQUEST,
				FINAL, // todo, change this maybe?
				0,
				0,
				0,
				parameters.Length(),
			},
			[8]byte{},
			[4]byte{0, 0, 0, 1},
			[4]byte{0xff, 0xff, 0xff, 0xff},
			CmdSN,
			ExpStatSN,
			[16]byte{},
		},
		parameters),
	}
}

type LoginRequest struct {
	PDU
}

func NewLoginRequest(parameters Parameters, CmdSN [4]byte) LoginRequest {
	res := LoginRequest{
		NewPDU(LoginRequestHeader{
			LoginHeader{
				BasicHeader{
					LOGIN_REQUEST + REQUEST_PDU,
					TRANSIT + CSG_LOGIN + NSG_FULL,
					VERSION_MAX,
					VERSION_MIN,
					0,
					parameters.Length(),
				},
				ISID_CISCO_OUI,
				TSIH_LOGIN,
				[4]byte{},
			},
			[4]byte{},
			CmdSN, //[4]byte{0, 0, 0, 1},
			[20]byte{},
		}, parameters),
	}
	return res
}

type LoginResponse struct {
	PDU
}

func NewLoginResponse() LoginResponse {
	return LoginResponse{PDU{new(LoginResponseHeader), Parameters{}}}
}

func Login2(loginParams map[string]string) []byte {
	// packet follows RFC convention of 4 byte "words"
	packet := [][]byte{
		[]byte{
			LOGIN_REQUEST + REQUEST_PDU,
			TRANSIT + CSG_LOGIN + NSG_FULL,
			VERSION_MAX,
			VERSION_MIN,
		},
		[]byte{0, 0, 0, 0}, // to be filled in later with AHS and data segment lengths
		ISID_CISCO_OUI[:4],
		append(ISID_CISCO_OUI[4:], TSIH_LOGIN[:]...),
		[]byte{0, 0, 0, 0}, // Initiator Task Tag can be 0
		[]byte{0, 0, 0, 0}, // Connection ID is 0x0, 0x0, other two bytes are reserved
		[]byte{0, 0, 0, 1}, // Command Sequence Number is 1
		[]byte{0, 0, 0, 0}, //reserved,
		[]byte{0, 0, 0, 0}, //reserved,
		[]byte{0, 0, 0, 0}, //reserved,
		[]byte{0, 0, 0, 0}, //reserved,
		[]byte{0, 0, 0, 0}, //reserved,
	}

	res := make([]byte, len(packet)*4)
	for i, bs := range packet {
		for j, b := range bs {
			res[i*4+j] = b
		}
	}
	// fill data segment with params
	l := 0 // length counter
	for param, value := range loginParams {
		paramb := []byte(param + "=" + value + "\u0000")
		l += len(paramb)
		res = append(res, paramb...)
	}
	padding := l % 4
	res = append(res, make([]byte, padding, padding)...)

	// according to RFC7143 (11.2.1.6), padding is excluded from length calculation
	// in case of weirdness, do: l += padding

	length := []byte{}
	fmt.Sscanf(fmt.Sprintf("%06x", l), "%x", &length)
	copy(res[5:8], length[:])
	return res
}
