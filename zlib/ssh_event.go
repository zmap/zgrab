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
