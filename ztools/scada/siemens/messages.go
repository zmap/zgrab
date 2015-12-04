package siemens

import (
	"encoding/binary"
	"errors"
)

// RFC 1006
type TPKTPacket struct {
	Version  byte
	Reserved byte
	Length   uint16
	Data     []byte
}

const tpktLength = 4 // 4 bytes (excluding Data slice)

// Encodes a TPKTPacket to binary
func (tpktPacket *TPKTPacket) Marshal() ([]byte, error) {

	totalLength := len(tpktPacket.Data) + tpktLength
	bytes := make([]byte, 0, totalLength)

	bytes = append(bytes, tpktPacket.Version)
	bytes = append(bytes, tpktPacket.Reserved)
	bytes = append(binary.LittleEndian.PutUint16(totalLength)...)
	bytes = append(bytes, tpktPacket.Data...)

	return bytes, nil
}

// Decodes a TPKTPacket from binary
func (tpktPacket *TPKTPacket) Unmarshal(bytes []byte) error {

	if len(bytes) < tpktLength {
		return errS7PacketTooShort
	}

	tpktPacket.Version = bytes[0]
	tpktPacket.Reserved = bytes[1]
	tpktPacket.Length = binary.LittleEndian.Uint16(bytes[2:4])
	tpktPacket.Data = bytes[tpktLength:]

	return nil
}

// RFC 892
type COTPConnectionPacket struct {
	DestinationRef  uint16
	SourceRef       uint16
	DestinationTSAP uint16
	SourceTSAP      uint16
	TPDUSize        byte
}

const cotpConnRequestLength = 18

// Encodes a COTPConnectionPacket to binary
func (cotpConnPacket *COTPConnectionPacket) Marshal() ([]byte, error) {
	bytes := make([]byte, 0, cotpConnRequestLength)

	bytes = append(bytes, byte(cotpConnRequestLength-1)) // length of packet (excluding 1-byte length header)
	bytes = append(bytes, byte(0xe0))                    // connection request code
	bytes = append(bytes, binary.LittleEndian.PutUint16(cotpConnPacket.DestinationRef)...)
	bytes = append(bytes, binary.LittleEndian.PutUint16(cotpConnPacket.SourceRef)...)
	bytes = append(bytes, byte(0))    // class 0 transport protocol with no flags
	bytes = append(bytes, byte(0xc1)) // code for identifier of the calling TSAP field
	bytes = append(bytes, byte(2))    // byte-length of subsequent field SourceTSAP
	bytes = append(bytes, binary.LittleEndian.PutUint16(cotpConnPacket.SourceTSAP)...)
	bytes = append(bytes, byte(0xc2)) // code fo identifier of the called TSAP field
	bytes = append(bytes, byte(2))    // byte-length of subsequent field DestinationTSAP
	bytes = append(bytes, binary.LittleEndian.PutUint16(cotpConnPacket.DestinationTSAP)...)
	bytes = append(bytes, byte(0xc0)) // code for proposed maximum TPDU size field
	bytes = append(bytes, byte(1))    // byte-length of subsequent field
	bytes = append(bytes, cotpConnPacket.TPDUSize)

	return bytes, nil
}

// Decodes a COTPConnectionPacket from binary that must be a connection confirmation
func (cotpConnPacket *COTPConnectionPacket) Unmarshal(bytes []byte) error {

	sizeByte := bytes[0]
	if sizeByte+1 != len(bytes) {
		return errS7PacketTooShort
	}
	pduType := bytes[1]
	if pduType != 0xd0 {
		return errors.New("Not a connection confirmation packet")
	}

	cotpConnPacket.DestinationRef = binary.LittleEndian.Uint16(bytes[2:4])
	cotpConnPacket.SourceRef = binary.LittleEndian.Uint16(bytes[4:6])
	// TODO: see if these need to be implemented
	//	cotpConnPacket.DestinationTSAP
	//	cotpConnPacket.SourceTSAP
	//	cotpConnPacket.TPDUSize

	return nil
}

type COTPDataPacket struct {
	Data []byte
}

const cotpDataPacketHeaderLength = 2

// Encodes a COTPDataPacket to binary
func (cotpDataPacket *COTPDataPacket) Marshal() ([]byte, error) {
	bytes := make([]byte, 0, cotpDataPacketHeaderLength+len(cotpDataPacket.Data))

	bytes = append(bytes, byte(2))    // data header length
	bytes = append(bytes, byte(0xf0)) // code for data packet
	bytes = append(bytes, byte(0x80)) // code for data packet
	bytes = append(bytes, cotpDataPacket.Data...)

	return bytes, nil
}

// Decodes a COTPDataPacket from binary
func (cotpDataPacket *COTPDataPacket) Unmarshal(bytes []byte) error {
	headerSize := bytes[0]

	if headerSize+1 > len(bytes) {
		return errInvalidPacket
	}

	cotpDataPacket.Data = bytes[headerSize+1:]

	return nil
}

type S7Packet struct {
	PDUType    byte
	RequestId  uint16
	Parameters []byte
	Data       []byte
	Error      uint16
}

const (
	S7_PROTOCOL_ID       = byte(0x32)
	S7_REQUEST           = byte(0x01)
	S7_REQUEST_USER_DATA = byte(0x07)
	S7_ACKNOWLEDGEMENT   = byte(0x02)
	S7_RESPONSE          = byte(0x03)
)

// Encodes a S7Packet to binary
func (s7Packet *S7Packet) Marshal() ([]byte, error) {

	if s7Packet.PDUType != S7_REQUEST || s7Packet.PDUType != S7_REQUEST_USER_DATA {
		return nil, errors.New("Invalid PDU request type")
	}

	bytes := make([]byte, 0, len(s7Packet))

	bytes = append(bytes, S7_PROTOCOL_ID) // s7 protocol id
	bytes = append(bytes, s7Packet.PDUType)
	bytes = append(bytes, binary.LittleEndian.PutUint16(0)...) // reserved
	bytes = append(bytes, binary.LittleEndian.PutUint16(s7Packet.RequestId)...)
	bytes = append(bytes, binary.LittleEndian.PutUint16(len(s7Packet.Parameters)))
	bytes = append(bytes, binary.LittleEndian.PutUint16(len(s7Packet.Data)))
	bytes = append(bytes, s7Packet.Parameters...)
	bytes = append(bytes, s7Packet.Data...)

	return bytes, nil
}

// Decodes a S7Packet from binary
func (s7Packet *S7Packet) Unmarshal(bytes []byte) error {
	if protocolId := bytes[0]; protocolId != S7_PROTOCOL_ID {
		return errNotS7
	}

	var headerSize int
	pduType := bytes[1]

	if pduType == S7_ACKNOWLEDGEMENT || pduType == S7_RESPONSE {
		headerSize = 12
		s7Packet.Error = binary.LittleEndian.Uint16(bytes[10:12])
	} else if pduType == S7_REQUEST || pduType == S7_REQUEST_USER_DATA {
		headerSize = 10
	} else {
		return errors.New("Unknown PDU type " + string(pduType))
	}

	s7Packet.PDUType = pduType
	s7Packet.RequestId = binary.LittleEndian.Uint16(bytes[4:6])
	paramLength := binary.LittleEndian.Uint16(bytes[6:8])
	dataLength := binary.LittleEndian.Uint16(bytes[8:10])

	s7Packet.Parameters = bytes[headerSize : headerSize+paramLength]
	s7Packet.Data = bytes[headerSize+paramLength : headerSize+paramLength+dataLength]

	return nil
}
