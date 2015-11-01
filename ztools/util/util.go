/*
 * ZGrab Copyright 2015 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

package util

import (
	"errors"
	"net"
	"regexp"
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
