// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ztls

import (
	"bytes"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/subtle"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strconv"

	"github.com/zmap/zgrab/ztools/x509"
)

type clientHandshakeState struct {
	c               *Conn
	serverHello     *serverHelloMsg
	hello           *clientHelloMsg
	suite           *cipherSuite
	finishedHash    finishedHash
	masterSecret    []byte
	preMasterSecret []byte
	session         *ClientSessionState
}

func (c *Conn) clientHandshake() error {
	if c.config == nil {
		c.config = defaultConfig()
	}

	var hello *clientHelloMsg

	var session *ClientSessionState
	var sessionCache ClientSessionCache
	var cacheKey string

	// first, let's check if a ClientHello template was provided by the user
	if c.config.ExternalClientHello != nil {

		hello = new(clientHelloMsg)

		if !hello.unmarshal(c.config.ExternalClientHello) {
			return errors.New("could not read the ClientHello provided")
		}

		// update the SNI with one name, whether or not the extension was already there
		hello.serverName = c.config.ServerName

		// then we update the 'raw' value of the message
		hello.raw = nil
		_ = hello.marshal()

		session = nil
		sessionCache = nil

	} else {

		if len(c.config.ServerName) == 0 && !c.config.InsecureSkipVerify {
			return errors.New("tls: either ServerName or InsecureSkipVerify must be specified in the tls.Config")
		}

		hello = &clientHelloMsg{
			vers:                 c.config.maxVersion(),
			compressionMethods:   []uint8{compressionNone},
			random:               make([]byte, 32),
			ocspStapling:         true,
			serverName:           c.config.ServerName,
			supportedCurves:      c.config.curvePreferences(),
			supportedPoints:      []uint8{pointFormatUncompressed},
			nextProtoNeg:         len(c.config.NextProtos) > 0,
			secureRenegotiation:  true,
			alpnProtocols:        c.config.NextProtos,
			extendedMasterSecret: c.config.maxVersion() >= VersionTLS10 && c.config.ExtendedMasterSecret,
		}

		if c.config.ForceSessionTicketExt {
			hello.ticketSupported = true
		}
		if c.config.SignedCertificateTimestampExt {
			hello.sctEnabled = true
		}

		if c.config.HeartbeatEnabled && !c.config.ExtendedRandom {
			hello.heartbeatEnabled = true
			hello.heartbeatMode = heartbeatModePeerAllowed
		}

		possibleCipherSuites := c.config.cipherSuites()
		hello.cipherSuites = make([]uint16, 0, len(possibleCipherSuites))

		if c.config.ForceSuites {
			hello.cipherSuites = possibleCipherSuites
		} else {

		NextCipherSuite:
			for _, suiteId := range possibleCipherSuites {
				for _, suite := range implementedCipherSuites {
					if suite.id != suiteId {
						continue
					}
					// Don't advertise TLS 1.2-only cipher suites unless
					// we're attempting TLS 1.2.
					if hello.vers < VersionTLS12 && suite.flags&suiteTLS12 != 0 {
						continue
					}
					hello.cipherSuites = append(hello.cipherSuites, suiteId)
					continue NextCipherSuite
				}
			}
		}

		if len(c.config.ClientRandom) == 32 {
			copy(hello.random, c.config.ClientRandom)
		} else {
			_, err := io.ReadFull(c.config.rand(), hello.random)
			if err != nil {
				c.sendAlert(alertInternalError)
				return errors.New("tls: short read from Rand: " + err.Error())
			}
		}

		if c.config.ExtendedRandom {
			hello.extendedRandomEnabled = true
			hello.extendedRandom = make([]byte, 32)
			if _, err := io.ReadFull(c.config.rand(), hello.extendedRandom); err != nil {
				return errors.New("tls: short read from Rand: " + err.Error())
			}
		}

		if hello.vers >= VersionTLS12 {
			hello.signatureAndHashes = c.config.signatureAndHashesForClient()
		}

		sessionCache = c.config.ClientSessionCache
		if c.config.SessionTicketsDisabled {
			sessionCache = nil
		}

		if sessionCache != nil {
			hello.ticketSupported = true

			// Try to resume a previously negotiated TLS session, if
			// available.
			cacheKey = clientSessionCacheKey(c.conn.RemoteAddr(), c.config)
			candidateSession, ok := sessionCache.Get(cacheKey)
			if ok {
				// Check that the ciphersuite/version used for the
				// previous session are still valid.
				cipherSuiteOk := false
				for _, id := range hello.cipherSuites {
					if id == candidateSession.cipherSuite {
						cipherSuiteOk = true
						break
					}
				}

				versOk := candidateSession.vers >= c.config.minVersion() &&
					candidateSession.vers <= c.config.maxVersion()
				if versOk && cipherSuiteOk {
					session = candidateSession
				}
			}
		}

		if session != nil {
			hello.sessionTicket = session.sessionTicket
			// A random session ID is used to detect when the
			// server accepted the ticket and is resuming a session
			// (see RFC 5077).
			hello.sessionId = make([]byte, 16)
			if _, err := io.ReadFull(c.config.rand(), hello.sessionId); err != nil {
				c.sendAlert(alertInternalError)
				return errors.New("tls: short read from Rand: " + err.Error())
			}
		}
	}

	c.handshakeLog = new(ServerHandshake)
	c.heartbleedLog = new(Heartbleed)

	c.writeRecord(recordTypeHandshake, hello.marshal())
	c.handshakeLog.ClientHello = hello.MakeLog()

	msg, err := c.readHandshake()
	if err != nil {
		return err
	}
	serverHello, ok := msg.(*serverHelloMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(serverHello, msg)
	}
	c.handshakeLog.ServerHello = serverHello.MakeLog()

	if serverHello.heartbeatEnabled {
		c.heartbeat = true
		c.heartbleedLog.HeartbeatEnabled = true
	}

	vers, ok := c.config.mutualVersion(serverHello.vers)
	if !ok {
		c.sendAlert(alertProtocolVersion)
		return fmt.Errorf("tls: server selected unsupported protocol version %x", serverHello.vers)
	}
	c.vers = vers
	c.haveVers = true

	suite := mutualCipherSuite(c.config.cipherSuites(), serverHello.cipherSuite)
	cipherImplemented := cipherIDInCipherList(serverHello.cipherSuite, implementedCipherSuites)
	cipherShared := cipherIDInCipherIDList(serverHello.cipherSuite, c.config.cipherSuites())
	if suite == nil {
		//c.sendAlert(alertHandshakeFailure)
		if !cipherShared {
			c.cipherError = ErrNoMutualCipher
		} else if !cipherImplemented {
			c.cipherError = ErrUnimplementedCipher
		}
	}

	hs := &clientHandshakeState{
		c:            c,
		serverHello:  serverHello,
		hello:        hello,
		suite:        suite,
		finishedHash: newFinishedHash(c.vers, suite),
		session:      session,
	}

	hs.finishedHash.Write(hs.hello.marshal())
	hs.finishedHash.Write(hs.serverHello.marshal())

	isResume, err := hs.processServerHello()
	if err != nil {
		return err
	}

	if isResume {
		if c.cipherError != nil {
			c.sendAlert(alertHandshakeFailure)
			return c.cipherError
		}
		if err := hs.establishKeys(); err != nil {
			return err
		}
		if err := hs.readSessionTicket(); err != nil {
			return err
		}
		if err := hs.readFinished(); err != nil {
			return err
		}
		if err := hs.sendFinished(); err != nil {
			return err
		}
	} else {
		if err := hs.doFullHandshake(); err != nil {
			return err
		}
		if err := hs.establishKeys(); err != nil {
			return err
		}
		if err := hs.sendFinished(); err != nil {
			return err
		}
		if err := hs.readSessionTicket(); err != nil {
			return err
		}
		if err := hs.readFinished(); err != nil {
			return err
		}
	}

	if hs.session == nil {
		c.handshakeLog.SessionTicket = nil
	} else {
		c.handshakeLog.SessionTicket = hs.session.MakeLog()
	}

	c.handshakeLog.KeyMaterial = hs.MakeLog()

	if sessionCache != nil && hs.session != nil && session != hs.session {
		sessionCache.Put(cacheKey, hs.session)
	}

	c.didResume = isResume
	c.handshakeComplete = true
	c.cipherSuite = suite.id
	return nil
}

func (hs *clientHandshakeState) doFullHandshake() error {
	c := hs.c

	msg, err := c.readHandshake()
	if err != nil {
		return err
	}

	var serverCert *x509.Certificate

	isAnon := hs.suite != nil && (hs.suite.flags&suiteAnon > 0)

	if !isAnon {

		certMsg, ok := msg.(*certificateMsg)
		if !ok || len(certMsg.certificates) == 0 {
			c.sendAlert(alertUnexpectedMessage)
			return unexpectedMessageError(certMsg, msg)
		}
		hs.finishedHash.Write(certMsg.marshal())

		certs := make([]*x509.Certificate, len(certMsg.certificates))
		invalidCert := false
		var invalidCertErr error
		for i, asn1Data := range certMsg.certificates {
			cert, err := x509.ParseCertificate(asn1Data)
			if err != nil {
				invalidCert = true
				invalidCertErr = err
				break
			}
			certs[i] = cert
		}

		c.handshakeLog.ServerCertificates = certMsg.MakeLog()

		if !invalidCert {
			opts := x509.VerifyOptions{
				Roots:         c.config.RootCAs,
				CurrentTime:   c.config.time(),
				DNSName:       c.config.ServerName,
				Intermediates: x509.NewCertPool(),
			}

			// Always check validity of the certificates
			for _, cert := range certs {
				/*
					if i == 0 {
						continue
					}
				*/
				opts.Intermediates.AddCert(cert)
			}
			var validation *x509.Validation
			c.verifiedChains, validation, err = certs[0].ValidateWithStupidDetail(opts)
			c.handshakeLog.ServerCertificates.addParsed(certs, validation)

			// If actually verifying and invalid, reject
			if !c.config.InsecureSkipVerify {
				if err != nil {
					c.sendAlert(alertBadCertificate)
					return err
				}
			}
		}

		if invalidCert {
			c.sendAlert(alertBadCertificate)
			return errors.New("tls: failed to parse certificate from server: " + invalidCertErr.Error())
		}

		c.peerCertificates = certs

		if hs.serverHello.ocspStapling {
			msg, err = c.readHandshake()
			if err != nil {
				return err
			}
			cs, ok := msg.(*certificateStatusMsg)
			if !ok {
				c.sendAlert(alertUnexpectedMessage)
				return unexpectedMessageError(cs, msg)
			}
			hs.finishedHash.Write(cs.marshal())

			if cs.statusType == statusTypeOCSP {
				c.ocspResponse = cs.response
			}
		}

		serverCert = certs[0]

		var supportedCertKeyType bool
		switch serverCert.PublicKey.(type) {
		case *rsa.PublicKey, *ecdsa.PublicKey, *x509.AugmentedECDSA:
			supportedCertKeyType = true
			break
		case *dsa.PublicKey:
			if c.config.ClientDSAEnabled {
				supportedCertKeyType = true
			}
		default:
			break
		}

		if !supportedCertKeyType {
			c.sendAlert(alertUnsupportedCertificate)
			return fmt.Errorf("tls: server's certificate contains an unsupported type of public key: %T", serverCert.PublicKey)
		}

		msg, err = c.readHandshake()
		if err != nil {
			return err
		}
	}

	// If we don't support the cipher, quit before we need to read the hs.suite
	// variable
	if c.cipherError != nil {
		return c.cipherError
	}

	skx, ok := msg.(*serverKeyExchangeMsg)

	keyAgreement := hs.suite.ka(c.vers)

	if ok {
		hs.finishedHash.Write(skx.marshal())

		err = keyAgreement.processServerKeyExchange(c.config, hs.hello, hs.serverHello, serverCert, skx)
		c.handshakeLog.ServerKeyExchange = skx.MakeLog(keyAgreement)
		if err != nil {
			c.sendAlert(alertUnexpectedMessage)
			return err
		}

		msg, err = c.readHandshake()
		if err != nil {
			return err
		}
	}

	var chainToSend *Certificate
	var certRequested bool
	certReq, ok := msg.(*certificateRequestMsg)
	if ok {
		certRequested = true

		// RFC 4346 on the certificateAuthorities field:
		// A list of the distinguished names of acceptable certificate
		// authorities. These distinguished names may specify a desired
		// distinguished name for a root CA or for a subordinate CA;
		// thus, this message can be used to describe both known roots
		// and a desired authorization space. If the
		// certificate_authorities list is empty then the client MAY
		// send any certificate of the appropriate
		// ClientCertificateType, unless there is some external
		// arrangement to the contrary.

		hs.finishedHash.Write(certReq.marshal())

		var rsaAvail, ecdsaAvail bool
		for _, certType := range certReq.certificateTypes {
			switch certType {
			case certTypeRSASign:
				rsaAvail = true
			case certTypeECDSASign:
				ecdsaAvail = true
			}
		}

		// We need to search our list of client certs for one
		// where SignatureAlgorithm is RSA and the Issuer is in
		// certReq.certificateAuthorities
	findCert:
		for i, chain := range c.config.Certificates {
			if !rsaAvail && !ecdsaAvail {
				continue
			}

			for j, cert := range chain.Certificate {
				x509Cert := chain.Leaf
				// parse the certificate if this isn't the leaf
				// node, or if chain.Leaf was nil
				if j != 0 || x509Cert == nil {
					if x509Cert, err = x509.ParseCertificate(cert); err != nil {
						c.sendAlert(alertInternalError)
						return errors.New("tls: failed to parse client certificate #" + strconv.Itoa(i) + ": " + err.Error())
					}
				}

				switch {
				case rsaAvail && x509Cert.PublicKeyAlgorithm == x509.RSA:
				case ecdsaAvail && x509Cert.PublicKeyAlgorithm == x509.ECDSA:
				default:
					continue findCert
				}

				if len(certReq.certificateAuthorities) == 0 {
					// they gave us an empty list, so just take the
					// first RSA cert from c.config.Certificates
					chainToSend = &chain
					break findCert
				}

				for _, ca := range certReq.certificateAuthorities {
					if bytes.Equal(x509Cert.RawIssuer, ca) {
						chainToSend = &chain
						break findCert
					}
				}
			}
		}

		msg, err = c.readHandshake()
		if err != nil {
			return err
		}
	}

	shd, ok := msg.(*serverHelloDoneMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(shd, msg)
	}
	hs.finishedHash.Write(shd.marshal())

	// If the server requested a certificate then we have to send a
	// Certificate message, even if it's empty because we don't have a
	// certificate to send.
	if certRequested {
		certMsg := new(certificateMsg)
		if chainToSend != nil {
			certMsg.certificates = chainToSend.Certificate
		}
		hs.finishedHash.Write(certMsg.marshal())
		c.writeRecord(recordTypeHandshake, certMsg.marshal())
	}

	preMasterSecret, ckx, err := keyAgreement.generateClientKeyExchange(c.config, hs.hello, serverCert)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}

	c.handshakeLog.ClientKeyExchange = ckx.MakeLog(keyAgreement)

	if ckx != nil {
		hs.finishedHash.Write(ckx.marshal())
		c.writeRecord(recordTypeHandshake, ckx.marshal())
	}

	if chainToSend != nil {
		var signed []byte
		certVerify := &certificateVerifyMsg{
			hasSignatureAndHash: c.vers >= VersionTLS12,
		}

		// Determine the hash to sign.
		var signatureType uint8
		switch c.config.Certificates[0].PrivateKey.(type) {
		case *ecdsa.PrivateKey:
			signatureType = signatureECDSA
		case *rsa.PrivateKey:
			signatureType = signatureRSA
		default:
			c.sendAlert(alertInternalError)
			return errors.New("unknown private key type")
		}
		certVerify.signatureAndHash, err = hs.finishedHash.selectClientCertSignatureAlgorithm(certReq.signatureAndHashes, c.config.signatureAndHashesForClient(), signatureType)
		if err != nil {
			c.sendAlert(alertInternalError)
			return err
		}
		digest, hashFunc, err := hs.finishedHash.hashForClientCertificate(certVerify.signatureAndHash, hs.masterSecret)
		if err != nil {
			c.sendAlert(alertInternalError)
			return err
		}

		switch key := c.config.Certificates[0].PrivateKey.(type) {
		case *ecdsa.PrivateKey:
			var r, s *big.Int
			r, s, err = ecdsa.Sign(c.config.rand(), key, digest)
			if err == nil {
				signed, err = asn1.Marshal(ecdsaSignature{r, s})
			}
		case *rsa.PrivateKey:
			signed, err = rsa.SignPKCS1v15(c.config.rand(), key, hashFunc, digest)
		default:
			err = errors.New("unknown private key type")
		}
		if err != nil {
			c.sendAlert(alertInternalError)
			return errors.New("tls: failed to sign handshake with client certificate: " + err.Error())
		}
		certVerify.signature = signed

		hs.writeClientHash(certVerify.marshal())
		c.writeRecord(recordTypeHandshake, certVerify.marshal())
	}

	var cr, sr []byte
	if hs.hello.extendedRandomEnabled {
		helloRandomLen := len(hs.hello.random)
		helloExtendedRandomLen := len(hs.hello.extendedRandom)

		cr = make([]byte, helloRandomLen+helloExtendedRandomLen)
		copy(cr, hs.hello.random)
		copy(cr[helloRandomLen:], hs.hello.extendedRandom)
	} else {
		cr = hs.hello.random
	}

	if hs.serverHello.extendedRandomEnabled {
		serverRandomLen := len(hs.serverHello.random)
		serverExtendedRandomLen := len(hs.serverHello.extendedRandom)

		sr = make([]byte, serverRandomLen+serverExtendedRandomLen)
		copy(sr, hs.serverHello.random)
		copy(sr[serverRandomLen:], hs.serverHello.extendedRandom)
	} else {
		sr = hs.serverHello.random
	}

	hs.preMasterSecret = make([]byte, len(preMasterSecret))
	copy(hs.preMasterSecret, preMasterSecret)

	if hs.serverHello.extendedMasterSecret && c.vers >= VersionTLS10 {
		hs.masterSecret = extendedMasterFromPreMasterSecret(c.vers, hs.suite, preMasterSecret, hs.finishedHash)
		c.extendedMasterSecret = true
	} else {
		hs.masterSecret = masterFromPreMasterSecret(c.vers, hs.suite, preMasterSecret, hs.hello.random, hs.serverHello.random)
	}

	return nil
}

func (hs *clientHandshakeState) establishKeys() error {
	c := hs.c

	clientMAC, serverMAC, clientKey, serverKey, clientIV, serverIV := keysFromMasterSecret(c.vers, hs.suite, hs.masterSecret, hs.hello.random, hs.serverHello.random, hs.suite.macLen, hs.suite.keyLen, hs.suite.ivLen)
	var clientCipher, serverCipher interface{}
	var clientHash, serverHash macFunction
	if hs.suite.cipher != nil {
		clientCipher = hs.suite.cipher(clientKey, clientIV, false /* not for reading */)
		clientHash = hs.suite.mac(c.vers, clientMAC)
		serverCipher = hs.suite.cipher(serverKey, serverIV, true /* for reading */)
		serverHash = hs.suite.mac(c.vers, serverMAC)
	} else {
		clientCipher = hs.suite.aead(clientKey, clientIV)
		serverCipher = hs.suite.aead(serverKey, serverIV)
	}

	c.in.prepareCipherSpec(c.vers, serverCipher, serverHash)
	c.out.prepareCipherSpec(c.vers, clientCipher, clientHash)
	return nil
}

func (hs *clientHandshakeState) serverResumedSession() bool {
	// If the server responded with the same sessionId then it means the
	// sessionTicket is being used to resume a TLS session.
	return hs.session != nil && hs.hello.sessionId != nil &&
		bytes.Equal(hs.serverHello.sessionId, hs.hello.sessionId)
}

func (hs *clientHandshakeState) processServerHello() (bool, error) {
	c := hs.c

	if hs.serverHello.compressionMethod != compressionNone {
		c.sendAlert(alertUnexpectedMessage)
		return false, errors.New("tls: server selected unsupported compression format")
	}

	clientDidNPN := hs.hello.nextProtoNeg
	clientDidALPN := len(hs.hello.alpnProtocols) > 0
	serverHasNPN := hs.serverHello.nextProtoNeg
	serverHasALPN := len(hs.serverHello.alpnProtocol) > 0

	if !clientDidNPN && serverHasNPN {
		c.sendAlert(alertHandshakeFailure)
		return false, errors.New("tls: server advertised unrequested NPN extension")
	}

	if !clientDidALPN && serverHasALPN {
		c.sendAlert(alertHandshakeFailure)
		return false, errors.New("tls: server advertised unrequested ALPN extension")
	}

	if serverHasNPN && serverHasALPN {
		c.sendAlert(alertHandshakeFailure)
		return false, errors.New("tls: server advertised both NPN and ALPN extensions")
	}

	if serverHasALPN {
		c.clientProtocol = hs.serverHello.alpnProtocol
		c.clientProtocolFallback = false
	}

	if hs.serverResumedSession() {
		// Restore masterSecret and peerCerts from previous state
		hs.masterSecret = hs.session.masterSecret
		c.extendedMasterSecret = hs.session.extendedMasterSecret
		c.peerCertificates = hs.session.serverCertificates
		return true, nil
	}
	return false, nil
}

func (hs *clientHandshakeState) readFinished() error {
	c := hs.c

	c.readRecord(recordTypeChangeCipherSpec)
	if err := c.in.error(); err != nil {
		return err
	}

	msg, err := c.readHandshake()
	if err != nil {
		return err
	}
	serverFinished, ok := msg.(*finishedMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(serverFinished, msg)
	}
	c.handshakeLog.ServerFinished = serverFinished.MakeLog()

	verify := hs.finishedHash.serverSum(hs.masterSecret)
	if len(verify) != len(serverFinished.verifyData) ||
		subtle.ConstantTimeCompare(verify, serverFinished.verifyData) != 1 {
		c.sendAlert(alertHandshakeFailure)
		return errors.New("tls: server's Finished message was incorrect")
	}
	hs.finishedHash.Write(serverFinished.marshal())
	return nil
}

func (hs *clientHandshakeState) readSessionTicket() error {
	if !hs.serverHello.ticketSupported {
		return nil
	}

	c := hs.c
	msg, err := c.readHandshake()
	if err != nil {
		return err
	}
	sessionTicketMsg, ok := msg.(*newSessionTicketMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(sessionTicketMsg, msg)
	}
	hs.finishedHash.Write(sessionTicketMsg.marshal())

	hs.session = &ClientSessionState{
		sessionTicket:      sessionTicketMsg.ticket,
		vers:               c.vers,
		cipherSuite:        hs.suite.id,
		masterSecret:       hs.masterSecret,
		serverCertificates: c.peerCertificates,
		lifetimeHint:       sessionTicketMsg.lifetimeHint,
	}

	return nil
}

func (hs *clientHandshakeState) sendFinished() error {
	c := hs.c

	c.writeRecord(recordTypeChangeCipherSpec, []byte{1})
	if hs.serverHello.nextProtoNeg {
		nextProto := new(nextProtoMsg)
		proto, fallback := mutualProtocol(c.config.NextProtos, hs.serverHello.nextProtos)
		nextProto.proto = proto
		c.clientProtocol = proto
		c.clientProtocolFallback = fallback

		hs.finishedHash.Write(nextProto.marshal())
		c.writeRecord(recordTypeHandshake, nextProto.marshal())
	}

	finished := new(finishedMsg)
	finished.verifyData = hs.finishedHash.clientSum(hs.masterSecret)
	hs.finishedHash.Write(finished.marshal())

	c.handshakeLog.ClientFinished = finished.MakeLog()

	c.writeRecord(recordTypeHandshake, finished.marshal())
	return nil
}

func (hs *clientHandshakeState) writeClientHash(msg []byte) {
	// writeClientHash is called before writeRecord.
	hs.writeHash(msg, 0)
}

func (hs *clientHandshakeState) writeServerHash(msg []byte) {
	// writeServerHash is called after readHandshake.
	hs.writeHash(msg, 0)
}

func (hs *clientHandshakeState) writeHash(msg []byte, seqno uint16) {
	hs.finishedHash.Write(msg)
}

// clientSessionCacheKey returns a key used to cache sessionTickets that could
// be used to resume previously negotiated TLS sessions with a server.
func clientSessionCacheKey(serverAddr net.Addr, config *Config) string {
	if len(config.ServerName) > 0 {
		return config.ServerName
	}
	return serverAddr.String()
}

// mutualProtocol finds the mutual Next Protocol Negotiation or ALPN protocol
// given list of possible protocols and a list of the preference order. The
// first list must not be empty. It returns the resulting protocol and flag
// indicating if the fallback case was reached.
func mutualProtocol(protos, preferenceProtos []string) (string, bool) {
	for _, s := range preferenceProtos {
		for _, c := range protos {
			if s == c {
				return s, false
			}
		}
	}

	return protos[0], true
}
