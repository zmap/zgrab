package siemens

import "errors"

var (
	errS7PacketTooShort error = errors.New("S7 packet too short")
	errInvalidPacket    error = errors.New("Invalid S7 packet")
	errNotS7            error = errors.New("Not a S7 packet")
)

type S7Error struct{}

var (
	S7_ERROR_CODES = map[uint32]string{
		// s7 data errors
		0x05: "Address error",
		0x0a: "Item not available",
		// s7 header errors
		0x8104: "Context not supported",
		0x8500: "Wrong PDU size",
	}
)

func (s7Error *S7Error) New(errorCode uint32) error {
	return errors.New(S7_ERROR_CODES[errorCode])
}
