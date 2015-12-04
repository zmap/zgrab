package siemens

import "errors"

var (
	errS7PacketTooShort error = errors.New("S7 packet too short")
	errInvalidPacket    error = errors.New("Invalid S7 packet")
	errNotS7            error = errors.New("Not a S7 packet")
)
