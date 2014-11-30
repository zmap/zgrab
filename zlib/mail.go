package zlib

import "encoding/json"

type MailBannerEvent struct {
	Banner string
}

var MailBannerEventType = EventType{
	TypeName:         CONNECTION_EVENT_MAIL_BANNER,
	GetEmptyInstance: func() EventData { return new(MailBannerEvent) },
}

type encodedMailBanner struct {
	Banner *string `json:"banner"`
}

func (mb *MailBannerEvent) GetType() EventType {
	return MailBannerEventType
}

func (mb *MailBannerEvent) MarshalJSON() ([]byte, error) {
	e := new(encodedMailBanner)
	if mb.Banner != "" {
		e.Banner = &mb.Banner
	}
	return json.Marshal(e)
}

func (mb *MailBannerEvent) UnmarshalJSON(b []byte) error {
	e := new(encodedMailBanner)
	if err := json.Unmarshal(b, &e); err != nil {
		return err
	}
	if e.Banner != nil {
		mb.Banner = *e.Banner
	}
	return nil
}

// An EHLOEvent represents the response to an EHLO
type EHLOEvent struct {
	Domain   string
	Response []byte
}

var EHLOEventType = EventType{
	TypeName:         CONNECTION_EVENT_EHLO_NAME,
	GetEmptyInstance: newEHLOEvent,
}

type encodedEHLOEvent struct {
	Response []byte `json:"response"`
}

func (e *EHLOEvent) GetType() EventType {
	return EHLOEventType
}

// MarshalJSON implements the json.Marshaler interface
func (e *EHLOEvent) MarshalJSON() ([]byte, error) {
	encoded := encodedEHLOEvent{
		Response: e.Response,
	}
	return json.Marshal(encoded)
}

// UnmarshalJSON implments the json.Unmarshal interface
func (e *EHLOEvent) UnmarshalJSON(b []byte) error {
	var encoded encodedEHLOEvent
	if err := json.Unmarshal(b, &encoded); err != nil {
		return err
	}
	e.Response = encoded.Response
	return nil
}

func newEHLOEvent() EventData {
	return new(EHLOEvent)
}

// A StartTLSEvent represents sending a StartTLS
type StartTLSEvent struct {
	Command  string
	Response []byte
}

var StartTLSEventType = EventType{
	TypeName:         CONNECTION_EVENT_STARTTLS_NAME,
	GetEmptyInstance: func() EventData { return new(StartTLSEvent) },
}

type encodedStartTLSEvent struct {
	Command  string
	Response []byte
}

func (s *StartTLSEvent) GetType() EventType {
	return StartTLSEventType
}

func (s *StartTLSEvent) MarshalJSON() ([]byte, error) {
	e := encodedStartTLSEvent{
		Command:  s.Command,
		Response: s.Response,
	}
	return json.Marshal(e)
}

func (s *StartTLSEvent) UnmarshalJSON(b []byte) error {
	var e encodedStartTLSEvent
	if err := json.Unmarshal(b, &e); err != nil {
		return err
	}
	s.Command = e.Command
	s.Response = e.Response
	return nil
}

// An SMTPHelpEvent represents sending a "HELP" message over SMTP
type SMTPHelpEvent struct {
	Response []byte
}

var SMTPHelpEventType = EventType{
	TypeName:         "smtp_help",
	GetEmptyInstance: func() EventData { return new(SMTPHelpEvent) },
}

func (h *SMTPHelpEvent) GetType() EventType {
	return SMTPHelpEventType
}

type encodedSMTPHelpEvent struct {
	Response []byte
}

func (h *SMTPHelpEvent) MarshalJSON() ([]byte, error) {
	e := encodedSMTPHelpEvent{
		Response: h.Response,
	}
	return json.Marshal(e)
}

func (h *SMTPHelpEvent) UnmarshalJSON(b []byte) error {
	var e encodedSMTPHelpEvent
	if err := json.Unmarshal(b, &e); err != nil {
		return err
	}
	h.Response = e.Response
	return nil
}
