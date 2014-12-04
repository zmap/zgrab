package main

import (
	"encoding/json"
	"time"
)

type Summary struct {
	Port       uint16
	Success    uint
	Failure    uint
	Total      uint
	StartTime  time.Time
	EndTime    time.Time
	Duration   time.Duration
	Senders    uint
	Timeout    time.Duration
	TLSVersion string
	MailType   string
	CAFile     string
}

type encodedSummary struct {
	Port       uint16        `json:"port"`
	Success    uint          `json:"success_count"`
	Failure    uint          `json:"failure_count"`
	Total      uint          `json:"total"`
	StartTime  string        `json:"start_time"`
	EndTime    string        `json:"end_time"`
	Duration   time.Duration `json:"duration"`
	Senders    uint          `json:"senders"`
	Timeout    uint          `json:"timeout"`
	TLSVersion *string       `json:"tls_version"`
	MailType   *string       `json:"mail_type"`
	CAFile     *string       `json:"ca_file_name"`
}

func (s *Summary) MarshalJSON() ([]byte, error) {
	e := new(encodedSummary)
	e.Port = s.Port
	e.Success = s.Success
	e.Failure = s.Failure
	e.Total = s.Total
	e.StartTime = s.StartTime.Format(time.RFC3339)
	e.EndTime = s.EndTime.Format(time.RFC3339)
	e.Duration = s.EndTime.Sub(s.StartTime) / time.Second
	e.Senders = s.Senders
	e.Timeout = uint(s.Timeout / time.Second)
	if s.TLSVersion != "" {
		e.TLSVersion = &s.TLSVersion
	}
	if s.MailType != "" {
		e.MailType = &s.MailType
	}
	if s.CAFile != "" {
		e.CAFile = &s.CAFile
	}
	return json.Marshal(e)
}

func (s *Summary) UnmarshalJSON(b []byte) error {
	e := new(encodedSummary)
	if err := json.Unmarshal(b, e); err != nil {
		return err
	}
	s.Port = e.Port
	s.Success = e.Success
	s.Failure = e.Failure
	s.Total = e.Total
	var err error
	if s.StartTime, err = time.Parse(time.RFC3339, e.StartTime); err != nil {
		return err
	}
	if s.EndTime, err = time.Parse(time.RFC3339, e.EndTime); err != nil {
		return err
	}
	s.Duration = s.EndTime.Sub(s.StartTime)
	s.Senders = e.Senders
	s.Timeout = time.Duration(e.Timeout) * time.Second
	if e.TLSVersion != nil {
		s.TLSVersion = *e.TLSVersion
	}
	if e.MailType != nil {
		s.MailType = *e.MailType
	}
	if e.CAFile != nil {
		s.CAFile = *e.CAFile
	}
	return nil
}
