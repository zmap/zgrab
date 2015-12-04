package siemens

import (
	"encoding/binary"
	"net"
)

func GetS7Banner(logStruct *S7Log, connection net.Conn) (err error) {

	// -------- Attempt connection
	connPacketBytes, err := makeCOTPConnectionPacketBytes(uint16(0x102), uint16(0x100))
	//	connPacketBytes, err := makeCOTPConnectionPacket(uint16(0x200), uint16(0x100)).Marshal()
	if err != nil {
		return err
	}

	connResponseBytes, err := sendRequestReadResponse(connection, connPacketBytes)
	if err != nil {
		return err
	}

	_, err = unmarshalCOTPConnectionResponse(connResponseBytes)
	if err != nil {
		return err
	}

	// -------- Negotiate S7

	requestPacketBytes, err := makeRequestPacketBytes(S7_REQUEST, makeNegotiatePDUParamBytes(), nil)
	if err != nil {
		return err
	}

	_, err = sendRequestReadResponse(connection, requestPacketBytes)
	if err != nil {
		return err
	}
	// -------- Make Module Identification request
	readRequestParamBytes := makeReadRequestParamBytes(uint16(0x11))
	readRequestBytes, err := makeRequestPacketBytes(S7_REQUEST, readRequestParamBytes, nil)

	readResponse, err := sendRequestReadResponse(connection, readRequestBytes)
	if err != nil {
		return err
	}

	logStruct.RawResponse = readResponse

	// -------- Make Component Identification request
	//	readRequest, err := makeReadRequestParamBytes(0x1c)

	return nil
}

func makeCOTPConnectionPacketBytes(dstTsap uint16, srcTsap uint16) ([]byte, error) {
	var cotpConnPacket COTPConnectionPacket
	cotpConnPacket.DestinationRef = uint16(0x00) // nmap uses 0x00
	cotpConnPacket.SourceRef = uint16(0x04)      // nmap uses 0x14
	cotpConnPacket.DestinationTSAP = dstTsap
	cotpConnPacket.SourceTSAP = srcTsap
	cotpConnPacket.TPDUSize = byte(0x0a) // nmap uses 0x0a

	cotpConnPacketBytes, err := cotpConnPacket.Marshal()
	if err != nil {
		return nil, err
	}

	var tpktPacket TPKTPacket
	tpktPacket.Data = cotpConnPacketBytes
	bytes, err := tpktPacket.Marshal()
	if err != nil {
		return nil, err
	}

	return bytes, nil
}

func makeRequestPacketBytes(pduType byte, parameters []byte, data []byte) ([]byte, error) {
	var s7Packet S7Packet
	s7Packet.PDUType = pduType
	s7Packet.RequestId = S7_REQUEST_ID
	s7Packet.Parameters = parameters
	s7Packet.Data = data
	s7PacketBytes, err := s7Packet.Marshal()
	if err != nil {
		return nil, err
	}

	var cotpDataPacket COTPDataPacket
	cotpDataPacket.Data = s7PacketBytes
	cotpDataPacketBytes, err := cotpDataPacket.Marshal()
	if err != nil {
		return nil, err
	}

	var tpktPacket TPKTPacket
	tpktPacket.Data = cotpDataPacketBytes
	bytes, err := tpktPacket.Marshal()
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

// Send a generic packet request and return the response
func sendRequestReadResponse(connection net.Conn, requestBytes []byte) ([]byte, error) {
	connection.Write(requestBytes)
	responseBytes := make([]byte, 1024)
	bytesRead, err := connection.Read(responseBytes)
	if err != nil {
		return nil, err
	}

	return responseBytes[0:bytesRead], nil
}

func unmarshalCOTPConnectionResponse(responseBytes []byte) (cotpConnPacket COTPConnectionPacket, err error) {
	var tpktPacket TPKTPacket
	if err := tpktPacket.Unmarshal(responseBytes); err != nil {
		return cotpConnPacket, err
	}

	if err := cotpConnPacket.Unmarshal(tpktPacket.Data); err != nil {
		return cotpConnPacket, err
	}

	return cotpConnPacket, nil
}

func makeNegotiatePDUParamBytes() (bytes []byte) {
	uint16BytesHolder := make([]byte, 2)
	bytes = make([]byte, 0, 8)        // fixed param length for negotiating PDU params
	bytes = append(bytes, byte(0xf0)) // negotiate PDU function code
	bytes = append(bytes, byte(0))    // ?
	binary.BigEndian.PutUint16(uint16BytesHolder, 0x01)
	bytes = append(bytes, uint16BytesHolder...) // min # of parallel jobs
	binary.BigEndian.PutUint16(uint16BytesHolder, 0x01)
	bytes = append(bytes, uint16BytesHolder...) // max # of parallel jobs

	return bytes
}

func makeReadRequestParamBytes(szlId uint16) (bytes []byte) {
	bytes = make([]byte, 0, 16)

	bytes = append(bytes, byte(0x00)) // magic parameter
	bytes = append(bytes, byte(0x01)) // magic parameter
	bytes = append(bytes, byte(0x12)) // magic parameter
	bytes = append(bytes, byte(0x04)) // param length
	bytes = append(bytes, byte(0x11)) // ?
	bytes = append(bytes, byte((S7_SZL_REQUEST*0x10)+S7_SZL_FUNCTIONS))
	bytes = append(bytes, byte(S7_SZL_READ))
	bytes = append(bytes, byte(0))
	bytes = append(bytes, byte(0xff))
	bytes = append(bytes, byte(0x09))

	// data section
	uint16BytesHolder := make([]byte, 2)
	binary.BigEndian.PutUint16(uint16BytesHolder, 4) // size of subsequent data
	bytes = append(bytes, uint16BytesHolder...)      // szl id
	binary.BigEndian.PutUint16(uint16BytesHolder, szlId)
	bytes = append(bytes, uint16BytesHolder...) // szl id
	binary.BigEndian.PutUint16(uint16BytesHolder, 1)
	bytes = append(bytes, uint16BytesHolder...) // szl index

	return bytes
}
