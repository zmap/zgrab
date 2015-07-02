/*
 * ZGrab Copyright 2015 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

package zlib

import "github.com/zmap/zgrab/ztools/ssh"

type SSHEvent struct {
	Handshake *ssh.HandshakeLog `json:"handshake"`
}

var SSHEventType = EventType{
	TypeName:         CONNECTION_EVENT_SSH_NAME,
	GetEmptyInstance: func() EventData { return new(SSHEvent) },
}

func (s *SSHEvent) GetType() EventType {
	return SSHEventType
}
