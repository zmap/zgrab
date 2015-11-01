/*
 * ZGrab Copyright 2015 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

package zftp

import (
	"net"
	"regexp"
	"strings"

	"github.com/zmap/zgrab/ztools/util"
)

var ftpEndRegex = regexp.MustCompile(`^(?:.*\r?\n)*([0-9]{3})( [^\r\n]*)?\r?\n$`)

func GatherFTPBanner(logStruct *FTPLog, connection net.Conn) error {
	buffer := make([]byte, 1024)
	respLen, err := util.ReadUntilRegex(connection, buffer, ftpEndRegex)
	logStruct.Banner = string(buffer[0:respLen])
	return err
}

func setupFTPS(logStruct *FTPLog, connection net.Conn) (bool, error) {
	buffer := make([]byte, 1024)

	connection.Write([]byte("AUTH TLS\r\n"))
	respLen, err := util.ReadUntilRegex(connection, buffer, ftpEndRegex)
	if err != nil {
		return false, err
	}

	logStruct.AuthTLSResp = string(buffer[0:respLen])
	retCode := ftpEndRegex.FindStringSubmatch(logStruct.AuthTLSResp)[1]
	if strings.HasPrefix(retCode, "2") {
		return true, nil
	} else {
		connection.Write([]byte("AUTH SSL\r\n"))
		respLen, err := util.ReadUntilRegex(connection, buffer, ftpEndRegex)
		if err != nil {
			return false, err
		}

		logStruct.AuthSSLResp = string(buffer[0:respLen])
		retCode := ftpEndRegex.FindStringSubmatch(logStruct.AuthSSLResp)[1]

		if strings.HasPrefix(retCode, "2") {
			return true, nil
		}
	}

	return false, nil
}

func GatherFTPSBanner(logStruct *FTPLog, connection net.Conn) (bool, error) {
	err := GatherFTPBanner(logStruct, connection)
	if err != nil {
		return false, err
	}

	retCode := ftpEndRegex.FindStringSubmatch(logStruct.Banner)[1]

	if strings.HasPrefix(retCode, "2") {
		return setupFTPS(logStruct, connection)
	} else {
		return false, nil
	}
}
