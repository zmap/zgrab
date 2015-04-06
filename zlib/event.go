package zlib

import (
	"encoding/json"
	"fmt"
)

type EventData interface {
	GetType() EventType
}

type EventType struct {
	TypeName         string
	GetEmptyInstance func() EventData
}

// MarshalJSON implements the json.Marshaler interface
func (e EventType) MarshalJSON() ([]byte, error) {
	return json.Marshal(e.TypeName)
}

var typeNameToTypeMap map[string]EventType

func init() {
	typeNameToTypeMap = make(map[string]EventType)
	RegisterEventType(ConnectEventType)
	RegisterEventType(ReadEventType)
	RegisterEventType(WriteEventType)
	RegisterEventType(TLSHandshakeEventType)
	RegisterEventType(HeartbleedEventType)
	RegisterEventType(EHLOEventType)
	RegisterEventType(StartTLSEventType)
	RegisterEventType(MailBannerEventType)
	RegisterEventType(ModbusEventType)
	RegisterEventType(FTPBannerEventType)
}

func RegisterEventType(t EventType) {
	name := t.TypeName
	if _, exists := typeNameToTypeMap[name]; exists {
		panic("Duplicate type name " + name)
	}
	typeNameToTypeMap[name] = t
}

func EventTypeFromName(name string) (EventType, error) {
	t, ok := typeNameToTypeMap[name]
	if !ok {
		return t, fmt.Errorf("Unknown type name %s", name)
	}
	return t, nil
}

const (
	CONNECTION_EVENT_CONNECT_NAME    = "connect"
	CONNECTION_EVENT_READ_NAME       = "read"
	CONNECTION_EVENT_WRITE_NAME      = "write"
	CONNECTION_EVENT_TLS_NAME        = "tls_handshake"
	CONNECTION_EVENT_HEARTBLEED_NAME = "heartbleed"
	CONNECTION_EVENT_EHLO_NAME       = "ehlo"
	CONNECTION_EVENT_STARTTLS_NAME   = "starttls"
	CONNECTION_EVENT_MAIL_BANNER     = "mail_banner"
	CONNECTION_EVENT_MODBUS          = "modbus"
	CONNECTION_EVENT_FTP             = "ftp"
	CONNECTION_EVENT_SSH_NAME        = "ssh"
)
