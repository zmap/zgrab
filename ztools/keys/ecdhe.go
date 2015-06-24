package keys

import (
	"crypto/elliptic"
	"encoding/json"
	"math/big"
)

// TLSCurveID is the type of a TLS identifier for an elliptic curve. See
// http://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-8
type TLSCurveID uint16

// ECDHParams stores elliptic-curve Diffie-Hellman paramters.At any point in
// time, it is unlikely that both ServerPrivate and ClientPrivate will be non-nil.
type ECDHParams struct {
	TLSCurveID    TLSCurveID     `json:"curve_id,omitempty"`
	Curve         elliptic.Curve `json:"-"`
	ServerPublic  *big.Int       `json:"server_public,omitempty"`
	ServerPrivate *big.Int       `json:"server_private,omitempty"`
	ClientPublic  *big.Int       `json:"client_public,omitempty"`
	ClientPrivate *big.Int       `json:"client_private,omitempty"`
	SessionKey    *big.Int       `json:"session_key,omitempty"`
}

// Description returns the description field for the given ID. See
// http://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-8
func (c *TLSCurveID) Description() string {
	if desc, ok := ecIDToName[*c]; ok {
		return desc
	}
	return "unknown"
}

// MarshalJSON implements the json.Marshaler interface
func (c *TLSCurveID) MarshalJSON() ([]byte, error) {
	aux := struct {
		Name string `json:"name"`
		ID   uint16 `json:"id"`
	}{
		Name: c.Description(),
		ID:   uint16(*c),
	}
	return json.Marshal(&aux)
}

//UnmarshalJSON implements the json.Unmarshaler interface
func (c *TLSCurveID) UnmarshalJSON(b []byte) error {
	aux := struct {
		ID uint16 `json:"id"`
	}{}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	*c = TLSCurveID(aux.ID)
	return nil
}
