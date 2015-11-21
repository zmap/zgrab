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

package telnet

import (
	"bytes"
	"errors"
	"net"
)

var (
	IAC                = byte(255) //Interpret as command
	DONT               = byte(254)
	DO                 = byte(253)
	WONT               = byte(252)
	WILL               = byte(251)
	IAC_CMD_LENGTH     = 3 // IAC commands take 3 bytes (inclusive)
	READ_BUFFER_LENGTH = 8192
)

func GetTelnetBanner(logStruct *TelnetLog, conn net.Conn) error {
	var err error
	if err = NegotiateOptions(logStruct, conn); err != nil {
		return err
	}

	//grab banner
	buffer := make([]byte, READ_BUFFER_LENGTH)

	numBytes := len(buffer)
	count := 0
	for numBytes != 0 && count < 15 {
		numBytes, err = conn.Read(buffer)
		logStruct.Banner = logStruct.Banner + string(buffer[0:numBytes])
		count += 1
	}

	return nil
}

func NegotiateOptions(logStruct *TelnetLog, conn net.Conn) error {
	buffer := make([]byte, READ_BUFFER_LENGTH)

	numBytes, err := conn.Read(buffer)

	if err != nil {
		return err
	}

	if numBytes == len(buffer) {
		return errors.New("Not enough buffer space for telnet options")
	}

	// Negotiate options
	retBuffer := make([]byte, READ_BUFFER_LENGTH)
	retBufferIndex := 0
	var option, optionType byte
	var iacIndex, prevIacIndex int
	prevIacIndex = 0
	for iacIndex = bytes.IndexByte(buffer, IAC); iacIndex != -1; iacIndex = bytes.IndexByte(buffer, IAC) {
		optionType = buffer[iacIndex+1]
		option = buffer[iacIndex+2]

		if optionType == WILL || optionType == WONT {
			optionType = DONT
		} else if option == DO || optionType == DONT {
			optionType = WONT
		} else {
			return errors.New("Unsupported telnet option type")
		}

		retBuffer[retBufferIndex] = IAC
		retBuffer[retBufferIndex+1] = optionType
		retBuffer[retBufferIndex+2] = option

		retBufferIndex += IAC_CMD_LENGTH
		prevIacIndex = iacIndex
	}

	// no more IAC commands, just read the resulting data
	logStruct.Banner = string(buffer[prevIacIndex:numBytes])

	if _, err = conn.Write(retBuffer); err != nil {
		return err
	}

	return nil
}
