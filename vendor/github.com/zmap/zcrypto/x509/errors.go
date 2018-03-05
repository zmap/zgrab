// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

import (
	"encoding/asn1"
	"fmt"
	"net"
	"strings"
)

// InvalidReason is an enumeration of the possible types of
// CertificateInvalidError
type InvalidReason int

const (
	// NotAuthorizedToSign results when a certificate is signed by another
	// which isn't marked as a CA certificate.
	NotAuthorizedToSign InvalidReason = iota

	// Expired results when a certificate has expired, based on the time
	// given in the VerifyOptions.
	Expired

	// CANotAuthorizedForThisName results when an intermediate or root
	// certificate has a name constraint which doesn't include the name
	// being checked.
	CANotAuthorizedForThisName

	// CANotAuthorizedForThisEmail results when an intermediate or root
	// certificate has a name constraint which doesn't include the email
	// being checked.
	CANotAuthorizedForThisEmail

	// CANotAuthorizedForThisIP results when an intermediate or root
	// certificate has a name constraint which doesn't include the IP
	// being checked.
	CANotAuthorizedForThisIP

	// CANotAuthorizedForThisDirectory results when an intermediate or root
	// certificate has a name constraint which doesn't include the directory
	// being checked.
	CANotAuthorizedForThisDirectory

	// TooManyIntermediates results when a path length constraint is
	// violated.
	TooManyIntermediates

	// IncompatibleUsage results when the certificate's key usage indicates
	// that it may only be used for a different purpose.
	IncompatibleUsage

	// NeverValid results when the certificate could never have been valid due to
	// some date-related issue, e.g. NotBefore > NotAfter.
	NeverValid

	// IsSelfSigned results when the certificate is self-signed and not a trusted
	// root.
	IsSelfSigned
)

// CertificateInvalidError results when an odd error occurs. Users of this
// library probably want to handle all these errors uniformly.
type CertificateInvalidError struct {
	Cert   *Certificate
	Reason InvalidReason
}

func (e CertificateInvalidError) Error() string {
	switch e.Reason {
	case NotAuthorizedToSign:
		return "x509: certificate is not authorized to sign other certificates"
	case Expired:
		return "x509: certificate has expired or is not yet valid"
	case CANotAuthorizedForThisName:
		return "x509: a root or intermediate certificate is not authorized to sign in this domain"
	case CANotAuthorizedForThisEmail:
		return "x509: a root or intermediate certificate is not authorized to sign this email address"
	case CANotAuthorizedForThisIP:
		return "x509: a root or intermediate certificate is not authorized to sign this IP address"
	case CANotAuthorizedForThisDirectory:
		return "x509: a root or intermediate certificate is not authorized to sign in this directory"
	case TooManyIntermediates:
		return "x509: too many intermediates for path length constraint"
	case IncompatibleUsage:
		return "x509: certificate specifies an incompatible key usage"
	case NeverValid:
		return "x509: certificate will never be valid"
	}
	return "x509: unknown error"
}

// HostnameError results when the set of authorized names doesn't match the
// requested name.
type HostnameError struct {
	Certificate *Certificate
	Host        string
}

func (h HostnameError) Error() string {
	c := h.Certificate

	var valid string
	if ip := net.ParseIP(h.Host); ip != nil {
		// Trying to validate an IP
		if len(c.IPAddresses) == 0 {
			return "x509: cannot validate certificate for " + h.Host + " because it doesn't contain any IP SANs"
		}
		for _, san := range c.IPAddresses {
			if len(valid) > 0 {
				valid += ", "
			}
			valid += san.String()
		}
	} else {
		if len(c.DNSNames) > 0 {
			valid = strings.Join(c.DNSNames, ", ")
		} else {
			valid = c.Subject.CommonName
		}
	}
	return "x509: certificate is valid for " + valid + ", not " + h.Host
}

// UnknownAuthorityError results when the certificate issuer is unknown
type UnknownAuthorityError struct {
	cert *Certificate
	// hintErr contains an error that may be helpful in determining why an
	// authority wasn't found.
	hintErr error
	// hintCert contains a possible authority certificate that was rejected
	// because of the error in hintErr.
	hintCert *Certificate
}

func (e UnknownAuthorityError) Error() string {
	s := "x509: certificate signed by unknown authority"
	if e.hintErr != nil {
		certName := e.hintCert.Subject.CommonName
		if len(certName) == 0 {
			if len(e.hintCert.Subject.Organization) > 0 {
				certName = e.hintCert.Subject.Organization[0]
			} else {
				certName = "serial:" + e.hintCert.SerialNumber.String()
			}
		}
		s += fmt.Sprintf(" (possibly because of %q while trying to verify candidate authority certificate %q)", e.hintErr, certName)
	}
	return s
}

// SystemRootsError results when we fail to load the system root certificates.
type SystemRootsError struct{}

func (SystemRootsError) Error() string {
	return "x509: failed to load system roots and no roots provided"
}

// UnhandledCriticalExtension results when the certificate contains an
// unimplemented X.509 extension marked as critical.
type UnhandledCriticalExtension struct {
	oid     asn1.ObjectIdentifier
	message string
}

func (h UnhandledCriticalExtension) Error() string {
	return fmt.Sprintf("x509: unhandled critical extension: %s | %s", h.oid, h.message)
}
