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

package dnp3

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

const (
	LINK_MIN_HEADER_LENGTH      = 10             // minimum link header length in bytes
	LINK_START_FIELD            = uint16(0x0564) // Pre-set 2 byte start field
	LINK_DIR_BIT                = 1              // Direction bit
	LINK_PRM_BIT                = 1              // Primary message bit
	LINK_FCB_BIT                = 0              // Frame count bit
	LINK_FCV_BIT                = 0              // Frame count valid bit
	LINK_BROADCAST_ADDRESS      = 0xFFFD         // Broadcast address w/o mandatory application response
	REQUEST_LINK_STATUS_CODE    = 0x9            // 4-bit function code for requesting link status
	LINK_STATUS_CODE            = 0xB            // 4-bit response function code for link status
	FUNCTION_CODE_NOT_SUPPORTED = 0xF            // Unsupported function code response
)

func GetDNP3Banner(logStruct *DNP3Log, connection net.Conn) (err error) {
	request := makeRequest()
	connection.Write(request)

	buffer := make([]byte, 8192)
	bytesRead, err := connection.Read(buffer)
	if err != nil && err != io.EOF {
		return err
	}

	logStruct.Banner = fmt.Sprintf("%X", buffer[0:bytesRead])

	return nil
}

func makeRequest() []byte {
	request := make([]byte, 0, LINK_MIN_HEADER_LENGTH)

	// 2-byte start field
	startField := make([]byte, 2)
	binary.BigEndian.PutUint16(startField, LINK_START_FIELD)
	request = append(request, startField...)

	//length byte
	lengthByte := byte(0x5)
	request = append(request, lengthByte)

	//control byte
	controlByte := byte(REQUEST_LINK_STATUS_CODE)
	controlByte = setBit(controlByte, 7, LINK_DIR_BIT)
	controlByte = setBit(controlByte, 6, LINK_PRM_BIT)
	controlByte = setBit(controlByte, 5, LINK_FCB_BIT)
	controlByte = setBit(controlByte, 4, LINK_FCV_BIT)
	request = append(request, controlByte)

	// 2-byte destination address
	destinationAddress := make([]byte, 2)
	binary.LittleEndian.PutUint16(destinationAddress, LINK_BROADCAST_ADDRESS)
	request = append(request, destinationAddress...)

	// 2-byte source address
	sourceAddress := make([]byte, 2)
	binary.LittleEndian.PutUint16(sourceAddress, 0x0000)
	request = append(request, sourceAddress...)

	//CRC
	crcCheck := make([]byte, 2)
	binary.LittleEndian.PutUint16(crcCheck, Crc16(request))
	request = append(request, crcCheck...)

	return request
}

func setBit(b byte, position uint32, value int) (result byte) {

	if value == 1 {
		result = b | (1 << position)
	} else if value == 0 {
		result = b & (^(1 << position))
	}

	return result
}
