// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

import (
	"reflect"
	"time"
)

// Certificate validity information
type CertificateValidity struct {
	// root, intermediate, or leaf certificate,
	Type string
	// Does this certificate chain up to any browser root store (via provided intermediates) or
	// server provided certificate chain
	TrustedPath bool
	// is this certificate currently valid in this browser,
	Valid bool
	// was this certificate ever valid in this browser
	WasValid bool
}

type ServerCertificateValidity struct {
	// Does this certificate chain up via server provided certificate chain
	CompletePath bool
	// is this certificate currently valid in this browser,
	Valid bool
	// error that caused potential invalidity
	Error string
}

type ServerCertificateValidation struct {
	Domain              string
	MatchesDomain       bool
	RootStoreValidities map[string]ServerCertificateValidity
}

// ValidateWithStupidDetail fills out a Validation struct given a leaf
// certificate and intermediates / roots. If opts.DNSName is set, then it will
// also check if the domain matches.
func (c *Certificate) ValidateWithStupidDetail(opts VerifyOptions) (chains [][]*Certificate, validation *ServerCertificateValidation) {

	// Manually set the time, so that all verifies we do get the same time
	if opts.CurrentTime.IsZero() {
		opts.CurrentTime = time.Now()
	}

	opts.KeyUsages = nil

	out := new(ServerCertificateValidation)
	out.Domain = opts.DNSName

	var fatalErr error
	var validationErrors *ValidationErrors
	if chains, validationErrors, fatalErr = c.Verify(opts); fatalErr != nil {
		out.MatchesDomain = false
		//out.BrowserTrusted = false
		//out.BrowserErrors = []string{fatalErr}
	} else if validationErrors != nil && validationErrors.HasError() {
		out.MatchesDomain = false
		//out.BrowserTrusted = false

		if !validationErrors.HasType(reflect.TypeOf(HostnameError{})) {
			// No HostnameError
			out.MatchesDomain = true
		} else if len(validationErrors.Errors) == 1 {
			// HostnameError is the only error
			//out.BrowserTrusted = true
		}
		//TODO: set out.BrowserError(s) properly
	} else {
		//out.BrowserTrusted = true
		if len(opts.DNSName) > 0 {
			out.MatchesDomain = true
		}
	}

	validation = out

	return
}
