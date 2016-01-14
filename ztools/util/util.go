/*
 * ZGrab Copyright 2015 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

package util

import (
	"bytes"
	"errors"
	"io"
	"io/ioutil"
	"math"
	"net"
	"regexp"
	"strings"
)

func ReadUntilRegex(connection net.Conn, res []byte, expr *regexp.Regexp) (int, error) {

	buf := res[0:]
	length := 0
	for finished := false; !finished; {
		n, err := connection.Read(buf)
		length += n
		if err != nil {
			return length, err
		}
		if expr.Match(res[0:length]) {
			finished = true
		}
		if length == len(res) {
			return length, errors.New("Not enough buffer space")
		}
		buf = res[length:]
	}
	return length, nil
}

// Checks for a strict TLD match
func TLDMatches(host1 string, host2 string) bool {
	splitStr1 := strings.Split(stripPortNumber(host1), ".")
	splitStr2 := strings.Split(stripPortNumber(host2), ".")

	tld1 := splitStr1[len(splitStr1)-1]
	tld2 := splitStr2[len(splitStr2)-1]

	return tld1 == tld2
}

func stripPortNumber(host string) string {
	return strings.Split(host, ":")[0]
}

/* Reads a io.Reader up to maxReadLen. If maxReadLen < 0, reads until EOF or nil. No-ops if maxReadLen == 0 */
func ReadString(reader io.Reader, maxReadLen int) (str string, err error) {

	var readBytes []byte
	var totalBytesRead int = 0

	if maxReadLen < 0 {
		readBytes, err = ioutil.ReadAll(reader)
		totalBytesRead = bytes.IndexByte(readBytes, 0)
	} else {
		READ_BUFFER_LEN := 8192

		buffer := make([]byte, READ_BUFFER_LEN)

		numBytes := len(buffer)
		rounds := int(math.Ceil(float64(maxReadLen) / float64(READ_BUFFER_LEN)))
		count := 0
		for numBytes != 0 && count < rounds && numBytes == READ_BUFFER_LEN {

			numBytes, err = reader.Read(buffer)

			if err != nil && err != io.EOF {
				return "", err
			}

			if count == rounds-1 {
				appendBytesLen := int(math.Min(float64(numBytes), float64(maxReadLen%READ_BUFFER_LEN)))
				readBytes = append(readBytes, buffer[0:appendBytesLen]...)
				totalBytesRead += appendBytesLen
			} else {
				readBytes = append(readBytes, buffer[0:numBytes]...)
				totalBytesRead += numBytes
			}
			count += 1
		}
	}

	return string(readBytes[:totalBytesRead]), nil
}
