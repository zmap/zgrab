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
	"fmt"
	"io"
	"math"
	"net"
)

const (
	IAC                = byte(255) //Interpret as command
	DONT               = byte(254)
	DO                 = byte(253)
	WONT               = byte(252)
	WILL               = byte(251)
	AYT                = byte(246) // Are you there
	IAC_CMD_LENGTH     = 3         // IAC commands take 3 bytes (inclusive)
	READ_BUFFER_LENGTH = 8192
)

func GetTelnetBanner(logStruct *TelnetLog, conn net.Conn, maxReadSize int) (err error) {
	if err = NegotiateOptions(logStruct, conn); err != nil {
		return err
	}

	//grab banner
	buffer := make([]byte, READ_BUFFER_LENGTH)

	numBytes := len(buffer)
	rounds := int(math.Ceil(float64(maxReadSize) / READ_BUFFER_LENGTH))
	count := 0
	for numBytes != 0 && count < rounds && numBytes == READ_BUFFER_LENGTH {

		numBytes, err = conn.Read(buffer)
		if err != nil && err != io.EOF {
			return err
		}
		if count == rounds-1 {
			logStruct.Banner = logStruct.Banner + string(buffer[0:maxReadSize%READ_BUFFER_LENGTH])
		} else {
			logStruct.Banner = logStruct.Banner + string(buffer[0:numBytes])
		}
		count += 1
	}

	return nil
}

func NegotiateOptions(logStruct *TelnetLog, conn net.Conn) error {
	var readBuffer, retBuffer []byte
	var option, optionType, returnOptionType byte
	var iacIndex, lastReadIndex, numBytes int
	var err error

	for finishedNegotiating := false; finishedNegotiating == false; {
		readBuffer = make([]byte, READ_BUFFER_LENGTH)
		retBuffer = nil
		numBytes, err = conn.Read(readBuffer)

		if err != nil {
			return err
		}

		if numBytes == len(readBuffer) {
			return errors.New("Not enough buffer space for telnet options")
		}

		// Negotiate options

		lastReadIndex = 0
		for iacIndex = bytes.IndexByte(readBuffer, IAC); iacIndex != -1; iacIndex = bytes.IndexByte(readBuffer, IAC) {
			optionType = readBuffer[iacIndex+1]
			option = readBuffer[iacIndex+2]

			// record all offered options
			if optionType == WILL || optionType == DO {
				logStruct.SupportedOpts = append(logStruct.SupportedOpts, fmt.Sprintf("%d", option))
			} else if optionType == WONT || optionType == DONT {
				logStruct.UnsupportedOpts = append(logStruct.UnsupportedOpts, fmt.Sprintf("%d", option))
			}

			// reject all offered options
			if optionType == WILL || optionType == WONT {
				returnOptionType = DONT
			} else if optionType == DO || optionType == DONT {
				returnOptionType = WONT
			} else {
				return errors.New("Unsupported telnet IAC option type" + fmt.Sprintf("%d", optionType))
			}

			retBuffer = append(retBuffer, IAC)
			retBuffer = append(retBuffer, returnOptionType)
			retBuffer = append(retBuffer, option)

			lastReadIndex += iacIndex + IAC_CMD_LENGTH
			readBuffer = readBuffer[iacIndex+IAC_CMD_LENGTH:]
		}

		if _, err = conn.Write(retBuffer); err != nil {
			return err
		}

		finishedNegotiating = numBytes != lastReadIndex
	}

	// no more IAC commands, just read the resulting data
	logStruct.Banner = string(readBuffer[lastReadIndex:numBytes])

	return nil
}
