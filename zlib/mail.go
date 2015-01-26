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
	Domain   string `json:"-"`
	Response string `json:"response"`
}

var EHLOEventType = EventType{
	TypeName:         CONNECTION_EVENT_EHLO_NAME,
	GetEmptyInstance: newEHLOEvent,
}

func (e *EHLOEvent) GetType() EventType {
	return EHLOEventType
}

func newEHLOEvent() EventData {
	return new(EHLOEvent)
}

// A StartTLSEvent represents sending a StartTLS
type StartTLSEvent struct {
	Command  string `json:"-"`
	Response string `json:"response"`
}

var StartTLSEventType = EventType{
	TypeName:         CONNECTION_EVENT_STARTTLS_NAME,
	GetEmptyInstance: func() EventData { return new(StartTLSEvent) },
}

func (s *StartTLSEvent) GetType() EventType {
	return StartTLSEventType
}

// An SMTPHelpEvent represents sending a "HELP" message over SMTP
type SMTPHelpEvent struct {
	Response string
}

var SMTPHelpEventType = EventType{
	TypeName:         "smtp_help",
	GetEmptyInstance: func() EventData { return new(SMTPHelpEvent) },
}

func (h *SMTPHelpEvent) GetType() EventType {
	return SMTPHelpEventType
}
