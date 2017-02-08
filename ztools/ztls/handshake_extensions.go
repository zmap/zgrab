package ztls

type NullExtension struct {
}

func (e NullExtension) Marshal() []byte {
	return []byte{}
}

type SniExtension struct {
	Domains      []string
	Autopopulate bool
}

func (e SniExtension) Marshal() []byte {
	result := []byte{}
	for _, domain := range e.Domains {
		current := make([]byte, 2+len(domain))
		copy(current[2:], []byte(domain))
		current[0] = uint8(len(domain) >> 8)
		current[1] = uint8(len(domain))
		result = append(result, current...)
	}
	sniHeader := make([]byte, 3)
	sniHeader[0] = uint8((len(result) + 1) >> 8)
	sniHeader[1] = uint8((len(result) + 1))
	sniHeader[2] = 0
	result = append(sniHeader, result...)

	extHeader := make([]byte, 4)
	extHeader[0] = 0
	extHeader[1] = 0
	extHeader[2] = uint8((len(result)) >> 8)
	extHeader[3] = uint8((len(result)))
	result = append(extHeader, result...)

	return result
}

type ALPNExtension struct {
	Protocols []string
}

func (e ALPNExtension) Marshal() []byte {
	result := []byte{}
	for _, protocol := range e.Protocols {
		current := make([]byte, 2+len(protocol))
		copy(current[2:], []byte(protocol))
		current[0] = uint8(len(protocol) >> 8)
		current[1] = uint8(len(protocol))
		result = append(result, current...)
	}
	alpnHeader := make([]byte, 2)
	alpnHeader[0] = uint8((len(result)) >> 8)
	alpnHeader[1] = uint8((len(result)))
	result = append(alpnHeader, result...)

	extHeader := make([]byte, 4)
	extHeader[0] = 0 //TK
	extHeader[1] = 0 //TK
	extHeader[2] = uint8((len(result)) >> 8)
	extHeader[3] = uint8((len(result)))
	result = append(extHeader, result...)

	return result
}

type SecureRenegotiationExtension struct {
}

func (e SecureRenegotiationExtension) Marshal() []byte {
	result := make([]byte, 5)
	result[0] = byte(extensionRenegotiationInfo >> 8)
	result[1] = byte(extensionRenegotiationInfo & 0xff)
	result[2] = 0
	result[3] = 1
	result[4] = 0
	return result
}

type ExtendedMasterSecretExtension struct {
}

func (e ExtendedMasterSecretExtension) Marshal() []byte {
	result := make([]byte, 4)
	result[0] = byte(extensionExtendedMasterSecret >> 8)
	result[1] = byte(extensionExtendedMasterSecret & 0xff)
	result[2] = 0
	result[3] = 0
	return result
}

type NextProtocolNegotiationExtension struct {
}

func (e NextProtocolNegotiationExtension) Marshal() []byte {
	result := make([]byte, 4)
	result[0] = byte(extensionNextProtoNeg >> 8)
	result[1] = byte(extensionNextProtoNeg & 0xff)
	result[2] = 0
	result[3] = 0
	return result
}

type StatusRequestExtension struct {
}

func (e StatusRequestExtension) Marshal() []byte {
	result := make([]byte, 9)
	result[0] = byte(extensionStatusRequest >> 8)
	result[1] = byte(extensionStatusRequest & 0xff)
	result[2] = 0
	result[3] = 5
	result[4] = 1 // OCSP type
	result[5] = 0
	result[6] = 0
	result[7] = 0
	result[8] = 0
	return result
}

type SCTExtension struct {
}

func (e SCTExtension) Marshal() []byte {
	result := make([]byte, 4)
	result[0] = byte(extensionSCT >> 8)
	result[1] = byte(extensionSCT & 0xff)
	result[2] = 0
	result[3] = 0
	return result
}

type SupportedCurvesExtension struct {
	Curves []CurveID
}

func (e SupportedCurvesExtension) Marshal() []byte {
	result := make([]byte, 6+2*len(e.Curves))
	result[0] = byte(extensionSupportedCurves >> 8)
	result[1] = byte(extensionSupportedCurves & 0xff)
	result[2] = uint8((2 + 2*len(e.Curves)) >> 8)
	result[3] = uint8((2 + 2*len(e.Curves)))
	result[4] = uint8((2 * len(e.Curves)) >> 8)
	result[5] = uint8((2 * len(e.Curves)))
	for i, curve := range e.Curves {
		result[6+2*i] = uint8(curve >> 8)
		result[7+2*i] = uint8(curve)
	}
	return result
}

type PointFormatExtension struct {
	Formats []uint8
}

func (e PointFormatExtension) Marshal() []byte {
	result := make([]byte, 5+len(e.Formats))
	result[0] = byte(extensionSupportedPoints >> 8)
	result[1] = byte(extensionSupportedPoints & 0xff)
	result[2] = uint8((1 + len(e.Formats)) >> 8)
	result[3] = uint8((1 + len(e.Formats)))
	result[4] = uint8((len(e.Formats)))
	for i, format := range e.Formats {
		result[5+i] = format
	}
	return result
}

type SessionTicketExtension struct {
	Ticket       []byte
	Autopopulate bool
}

func (e SessionTicketExtension) Marshal() []byte {
	result := make([]byte, 4+len(e.Ticket))
	result[0] = byte(extensionSessionTicket >> 8)
	result[1] = byte(extensionSessionTicket & 0xff)
	result[2] = uint8(len(e.Ticket) >> 8)
	result[3] = uint8(len(e.Ticket))
	if len(e.Ticket) > 0 {
		copy(result[4:], e.Ticket)
	}
	return result
}

type HeartbeatExtension struct {
	Mode byte
}

func (e HeartbeatExtension) Marshal() []byte {
	result := make([]byte, 5)
	result[0] = byte(extensionHeartbeat >> 8)
	result[1] = byte(extensionHeartbeat & 0xff)
	result[2] = uint8(1 >> 8)
	result[3] = uint8(1)
	result[4] = e.Mode
	return result
}

type SignatureAlgorithmExtension struct {
	SignatureAndHashes []uint16
}

func (e SignatureAlgorithmExtension) getStruct() []signatureAndHash {
	result := make([]signatureAndHash, len(e.SignatureAndHashes))
	for i, alg := range e.SignatureAndHashes {
		result[i].hash = uint8(alg >> 8)
		result[i].signature = uint8(alg)
	}
	return result
}

func (e SignatureAlgorithmExtension) Marshal() []byte {
	result := make([]byte, 6+2*len(e.SignatureAndHashes))
	result[0] = byte(extensionSignatureAlgorithms >> 8)
	result[1] = byte(extensionSignatureAlgorithms & 0xff)
	result[2] = uint8((2 + 2*len(e.SignatureAndHashes)) >> 8)
	result[3] = uint8((2 + 2*len(e.SignatureAndHashes)))
	result[4] = uint8((2 * len(e.SignatureAndHashes)) >> 8)
	result[5] = uint8((2 * len(e.SignatureAndHashes)))
	for i, pair := range e.getStruct() {
		result[6+2*i] = uint8(pair.hash)
		result[7+2*i] = uint8(pair.signature)
	}
	return result
}
