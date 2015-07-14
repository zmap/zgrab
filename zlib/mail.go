/*
 * ZGrab Copyright 2015 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

package zlib

// An EHLOEvent represents the response to an EHLO
type EHLOEvent struct {
	Domain   string `json:"-"`
	Response string `json:"response"`
}

// A StartTLSEvent represents sending a StartTLS
type StartTLSEvent struct {
	Command  string `json:"-"`
	Response string `json:"response"`
}

// An SMTPHelpEvent represents sending a "HELP" message over SMTP
type SMTPHelpEvent struct {
	Response string
}
