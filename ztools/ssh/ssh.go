package ssh

import (
	"errors"
	"net"
)

var errShortPacket = errors.New("SSH packet too short")
var errLongPacket = errors.New("SSH packet too long")
var errInvalidPadding = errors.New("Invalid SSH padding")
var errUnexpectedMessage = errors.New("Unexpected SSH message type")

// Client wraps a network connection with an SSH client connection
func Client(c net.Conn) *Conn {
	return &Conn{
		conn: c,
	}
}

// SSH message types. These are usually the first byte of the payload
const (
	SSH_MSG_KEXINIT byte = 0x14
)
