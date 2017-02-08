// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ztls

import (
	"container/list"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/zmap/zgrab/ztools/x509"
)

const (
	VersionSSL30 = 0x0300
	VersionTLS10 = 0x0301
	VersionTLS11 = 0x0302
	VersionTLS12 = 0x0303
)

const (
	maxPlaintext        = 16384        // maximum plaintext payload length
	maxCiphertext       = 16384 + 2048 // maximum ciphertext payload length
	tlsRecordHeaderLen  = 5            // record header length
	dtlsRecordHeaderLen = 13
	maxHandshake        = 65536 // maximum handshake we support (protocol max is 16 MB)

	minVersion = VersionSSL30
	maxVersion = VersionTLS12
)

// TLS record types.
type recordType uint8

const (
	recordTypeChangeCipherSpec recordType = 20
	recordTypeAlert            recordType = 21
	recordTypeHandshake        recordType = 22
	recordTypeApplicationData  recordType = 23
)

// TLS handshake message types.
const (
	typeHelloRequest        uint8 = 0
	typeClientHello         uint8 = 1
	typeServerHello         uint8 = 2
	typeHelloVerifyRequest  uint8 = 3
	typeNewSessionTicket    uint8 = 4
	typeCertificate         uint8 = 11
	typeServerKeyExchange   uint8 = 12
	typeCertificateRequest  uint8 = 13
	typeServerHelloDone     uint8 = 14
	typeCertificateVerify   uint8 = 15
	typeClientKeyExchange   uint8 = 16
	typeFinished            uint8 = 20
	typeCertificateStatus   uint8 = 22
	typeNextProtocol        uint8 = 67  // Not IANA assigned
	typeEncryptedExtensions uint8 = 203 // Not IANA assigned
)

// TLS compression types.
const (
	compressionNone uint8 = 0
)

// TLS extension numbers
const (
	extensionServerName           uint16 = 0
	extensionStatusRequest        uint16 = 5
	extensionSupportedCurves      uint16 = 10
	extensionSupportedPoints      uint16 = 11
	extensionSignatureAlgorithms  uint16 = 13
	extensionALPN                 uint16 = 16
	extensionExtendedMasterSecret uint16 = 23
	extensionSessionTicket        uint16 = 35
	extensionNextProtoNeg         uint16 = 13172 // not IANA assigned
	extensionRenegotiationInfo    uint16 = 0xff01
	extensionExtendedRandom       uint16 = 0x0028 // not IANA assigned
	extensionSCT                  uint16 = 18
)

// TLS signaling cipher suite values
const (
	scsvRenegotiation uint16 = 0x00ff
)

// CurveID is the type of a TLS identifier for an elliptic curve. See
// http://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-8
type CurveID uint16

const (
	CurveP256 CurveID = 23
	CurveP384 CurveID = 24
	CurveP521 CurveID = 25
)

// TLS Elliptic Curve Point Formats
// http://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-9
const (
	pointFormatUncompressed uint8 = 0
)

// TLS CertificateStatusType (RFC 3546)
const (
	statusTypeOCSP uint8 = 1
)

// Certificate types (for certificateRequestMsg)
const (
	certTypeRSASign    = 1 // A certificate containing an RSA key
	certTypeDSSSign    = 2 // A certificate containing a DSA key
	certTypeRSAFixedDH = 3 // A certificate containing a static DH key
	certTypeDSSFixedDH = 4 // A certificate containing a static DH key

	// See RFC4492 sections 3 and 5.5.
	certTypeECDSASign      = 64 // A certificate containing an ECDSA-capable public key, signed with ECDSA.
	certTypeRSAFixedECDH   = 65 // A certificate containing an ECDH-capable public key, signed with RSA.
	certTypeECDSAFixedECDH = 66 // A certificate containing an ECDH-capable public key, signed with ECDSA.

	// Rest of these are reserved by the TLS spec
)

// Hash functions for TLS 1.2 (See RFC 5246, section A.4.1)
const (
	hashMD5    uint8 = 1
	hashSHA1   uint8 = 2
	hashSHA224 uint8 = 3
	hashSHA256 uint8 = 4
	hashSHA384 uint8 = 5
	hashSHA512 uint8 = 6
)

// Signature algorithms for TLS 1.2 (See RFC 5246, section A.4.1)
const (
	signatureRSA   uint8 = 1
	signatureDSA   uint8 = 2
	signatureECDSA uint8 = 3
)

// signatureAndHash mirrors the TLS 1.2, SignatureAndHashAlgorithm struct. See
// RFC 5246, section A.4.1.
type signatureAndHash struct {
	signature, hash uint8
}

// supportedSKXSignatureAlgorithms contains the signature and hash algorithms
// that the code advertises as supported in a TLS 1.2 ClientHello.
var supportedSKXSignatureAlgorithms = []signatureAndHash{
	{signatureRSA, hashSHA256},
	{signatureECDSA, hashSHA256},
	{signatureRSA, hashSHA1},
	{signatureECDSA, hashSHA1},
	{signatureDSA, hashSHA1},
}

var defaultSKXSignatureAlgorithms = []signatureAndHash{
	{signatureRSA, hashSHA256},
	{signatureECDSA, hashSHA256},
	{signatureRSA, hashSHA1},
	{signatureECDSA, hashSHA1},
}

// supportedClientCertSignatureAlgorithms contains the signature and hash
// algorithms that the code advertises as supported in a TLS 1.2
// CertificateRequest.
var supportedClientCertSignatureAlgorithms = []signatureAndHash{
	{signatureRSA, hashSHA256},
	{signatureECDSA, hashSHA256},
}

// ConnectionState records basic TLS details about the connection.
type ConnectionState struct {
	Version                    uint16                // TLS version used by the connection (e.g. VersionTLS12)
	HandshakeComplete          bool                  // TLS handshake is complete
	DidResume                  bool                  // connection resumes a previous TLS connection
	CipherSuite                uint16                // cipher suite in use (TLS_RSA_WITH_RC4_128_SHA, ...)
	NegotiatedProtocol         string                // negotiated next protocol (from Config.NextProtos)
	NegotiatedProtocolIsMutual bool                  // negotiated protocol was advertised by server
	ServerName                 string                // server name requested by client, if any (server side only)
	PeerCertificates           []*x509.Certificate   // certificate chain presented by remote peer
	VerifiedChains             [][]*x509.Certificate // verified chains built from PeerCertificates
}

// ClientAuthType declares the policy the server will follow for
// TLS Client Authentication.
type ClientAuthType int

const (
	NoClientCert ClientAuthType = iota
	RequestClientCert
	RequireAnyClientCert
	VerifyClientCertIfGiven
	RequireAndVerifyClientCert
)

// ClientSessionState contains the state needed by clients to resume TLS
// sessions.
type ClientSessionState struct {
	sessionTicket        []uint8             // Encrypted ticket used for session resumption with server
	lifetimeHint         uint32              // Hint from server about how long the session ticket should be stored
	vers                 uint16              // SSL/TLS version negotiated for the session
	cipherSuite          uint16              // Ciphersuite negotiated for the session
	masterSecret         []byte              // MasterSecret generated by client on a full handshake
	serverCertificates   []*x509.Certificate // Certificate chain presented by the server
	extendedMasterSecret bool                // Whether an extended master secret was used to generate the session
}

// ClientSessionCache is a cache of ClientSessionState objects that can be used
// by a client to resume a TLS session with a given server. ClientSessionCache
// implementations should expect to be called concurrently from different
// goroutines.
type ClientSessionCache interface {
	// Get searches for a ClientSessionState associated with the given key.
	// On return, ok is true if one was found.
	Get(sessionKey string) (session *ClientSessionState, ok bool)

	// Put adds the ClientSessionState to the cache with the given key.
	Put(sessionKey string, cs *ClientSessionState)
}

// A Config structure is used to configure a TLS client or server.
// After one has been passed to a TLS function it must not be
// modified. A Config may be reused; the tls package will also not
// modify it.
type Config struct {
	// Rand provides the source of entropy for nonces and RSA blinding.
	// If Rand is nil, TLS uses the cryptographic random reader in package
	// crypto/rand.
	// The Reader must be safe for use by multiple goroutines.
	Rand io.Reader

	// Time returns the current time as the number of seconds since the epoch.
	// If Time is nil, TLS uses time.Now.
	Time func() time.Time

	// Certificates contains one or more certificate chains
	// to present to the other side of the connection.
	// Server configurations must include at least one certificate.
	Certificates []Certificate

	// NameToCertificate maps from a certificate name to an element of
	// Certificates. Note that a certificate name can be of the form
	// '*.example.com' and so doesn't have to be a domain name as such.
	// See Config.BuildNameToCertificate
	// The nil value causes the first element of Certificates to be used
	// for all connections.
	NameToCertificate map[string]*Certificate

	// RootCAs defines the set of root certificate authorities
	// that clients use when verifying server certificates.
	// If RootCAs is nil, TLS uses the host's root CA set.
	RootCAs *x509.CertPool

	// NextProtos is a list of supported, application level protocols.
	NextProtos []string

	// ServerName is used to verify the hostname on the returned
	// certificates unless InsecureSkipVerify is given. It is also included
	// in the client's handshake to support virtual hosting.
	ServerName string

	// ClientAuth determines the server's policy for
	// TLS Client Authentication. The default is NoClientCert.
	ClientAuth ClientAuthType

	// ClientCAs defines the set of root certificate authorities
	// that servers use if required to verify a client certificate
	// by the policy in ClientAuth.
	ClientCAs *x509.CertPool

	// InsecureSkipVerify controls whether a client verifies the
	// server's certificate chain and host name.
	// If InsecureSkipVerify is true, TLS accepts any certificate
	// presented by the server and any host name in that certificate.
	// In this mode, TLS is susceptible to man-in-the-middle attacks.
	// This should be used only for testing.
	InsecureSkipVerify bool

	// CipherSuites is a list of supported cipher suites. If CipherSuites
	// is nil, TLS uses a list of suites supported by the implementation.
	CipherSuites []uint16

	// PreferServerCipherSuites controls whether the server selects the
	// client's most preferred ciphersuite, or the server's most preferred
	// ciphersuite. If true then the server's preference, as expressed in
	// the order of elements in CipherSuites, is used.
	PreferServerCipherSuites bool

	// SessionTicketsDisabled may be set to true to disable session ticket
	// (resumption) support.
	SessionTicketsDisabled bool

	// SessionTicketKey is used by TLS servers to provide session
	// resumption. See RFC 5077. If zero, it will be filled with
	// random data before the first server handshake.
	//
	// If multiple servers are terminating connections for the same host
	// they should all have the same SessionTicketKey. If the
	// SessionTicketKey leaks, previously recorded and future TLS
	// connections using that key are compromised.
	SessionTicketKey [32]byte

	// SessionCache is a cache of ClientSessionState entries for TLS session
	// resumption.
	ClientSessionCache ClientSessionCache

	// MinVersion contains the minimum SSL/TLS version that is acceptable.
	// If zero, then SSLv3 is taken as the minimum.
	MinVersion uint16

	// MaxVersion contains the maximum SSL/TLS version that is acceptable.
	// If zero, then the maximum version supported by this package is used,
	// which is currently TLS 1.2.
	MaxVersion uint16

	// CurvePreferences contains the elliptic curves that will be used in
	// an ECDHE handshake, in preference order. If empty, the default will
	// be used.
	CurvePreferences []CurveID

	serverInitOnce sync.Once // guards calling (*Config).serverInit

	ForceSuites bool

	// Export RSA Key
	ExportRSAKey *rsa.PrivateKey

	// HeartbeatEnabled sets whether the heartbeat extension is sent
	HeartbeatEnabled bool

	// ClientDSAEnabled sets whether a TLS client will accept server DSA keys
	// and DSS signatures
	ClientDSAEnabled bool

	// Use extended random
	ExtendedRandom bool

	// Force Client Hello to send TLS Session Ticket extension
	ForceSessionTicketExt bool

	// Enable use of the Extended Master Secret extension
	ExtendedMasterSecret bool

	SignedCertificateTimestampExt bool

	// Explicitly set Client random
	ClientRandom []byte

	// Explicitly set ClientHello with raw data
	ExternalClientHello []byte
}

func (c *Config) serverInit() {
	if c.SessionTicketsDisabled {
		return
	}

	// If the key has already been set then we have nothing to do.
	for _, b := range c.SessionTicketKey {
		if b != 0 {
			return
		}
	}

	if _, err := io.ReadFull(c.rand(), c.SessionTicketKey[:]); err != nil {
		c.SessionTicketsDisabled = true
	}
}

func (c *Config) rand() io.Reader {
	r := c.Rand
	if r == nil {
		return rand.Reader
	}
	return r
}

func (c *Config) time() time.Time {
	t := c.Time
	if t == nil {
		t = time.Now
	}
	return t()
}

func (c *Config) cipherSuites() []uint16 {
	s := c.CipherSuites
	if s == nil {
		s = defaultCipherSuites()
	}
	return s
}

func (c *Config) minVersion() uint16 {
	if c == nil || c.MinVersion == 0 {
		return minVersion
	}
	return c.MinVersion
}

func (c *Config) maxVersion() uint16 {
	if c == nil || c.MaxVersion == 0 {
		return maxVersion
	}
	return c.MaxVersion
}

var defaultCurvePreferences = []CurveID{CurveP256, CurveP384, CurveP521}

func (c *Config) curvePreferences() []CurveID {
	if c == nil || len(c.CurvePreferences) == 0 {
		return defaultCurvePreferences
	}
	return c.CurvePreferences
}

// mutualVersion returns the protocol version to use given the advertised
// version of the peer.
func (c *Config) mutualVersion(vers uint16) (uint16, bool) {
	minVersion := c.minVersion()
	maxVersion := c.maxVersion()

	if vers < minVersion {
		return 0, false
	}
	if vers > maxVersion {
		vers = maxVersion
	}
	return vers, true
}

// getCertificateForName returns the best certificate for the given name,
// defaulting to the first element of c.Certificates if there are no good
// options.
func (c *Config) getCertificateForName(name string) *Certificate {
	if len(c.Certificates) == 1 || c.NameToCertificate == nil {
		// There's only one choice, so no point doing any work.
		return &c.Certificates[0]
	}

	name = strings.ToLower(name)
	for len(name) > 0 && name[len(name)-1] == '.' {
		name = name[:len(name)-1]
	}

	if cert, ok := c.NameToCertificate[name]; ok {
		return cert
	}

	// try replacing labels in the name with wildcards until we get a
	// match.
	labels := strings.Split(name, ".")
	for i := range labels {
		labels[i] = "*"
		candidate := strings.Join(labels, ".")
		if cert, ok := c.NameToCertificate[candidate]; ok {
			return cert
		}
	}

	// If nothing matches, return the first certificate.
	return &c.Certificates[0]
}

func (c *Config) signatureAndHashesForServer() []signatureAndHash {
	/*
		if c != nil && c.SignatureAndHashes != nil {
			return c.SignatureAndHashes
		}
	*/
	return supportedClientCertSignatureAlgorithms
}

func (c *Config) signatureAndHashesForClient() []signatureAndHash {
	/*
		if c != nil && c.SignatureAndHashes != nil {
			return c.SignatureAndHashes
		}
	*/
	if c.ClientDSAEnabled {
		return supportedSKXSignatureAlgorithms
	}
	return defaultSKXSignatureAlgorithms
}

// BuildNameToCertificate parses c.Certificates and builds c.NameToCertificate
// from the CommonName and SubjectAlternateName fields of each of the leaf
// certificates.
func (c *Config) BuildNameToCertificate() {
	c.NameToCertificate = make(map[string]*Certificate)
	for i := range c.Certificates {
		cert := &c.Certificates[i]
		x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			continue
		}
		if len(x509Cert.Subject.CommonName) > 0 {
			c.NameToCertificate[x509Cert.Subject.CommonName] = cert
		}
		for _, san := range x509Cert.DNSNames {
			c.NameToCertificate[san] = cert
		}
	}
}

// A Certificate is a chain of one or more certificates, leaf first.
type Certificate struct {
	Certificate [][]byte
	PrivateKey  crypto.PrivateKey // supported types: *rsa.PrivateKey, *ecdsa.PrivateKey
	// OCSPStaple contains an optional OCSP response which will be served
	// to clients that request it.
	OCSPStaple []byte
	// Leaf is the parsed form of the leaf certificate, which may be
	// initialized using x509.ParseCertificate to reduce per-handshake
	// processing for TLS clients doing client authentication. If nil, the
	// leaf certificate will be parsed as needed.
	Leaf *x509.Certificate
}

// A TLS record.
type record struct {
	contentType  recordType
	major, minor uint8
	payload      []byte
}

type handshakeMessage interface {
	marshal() []byte
	unmarshal([]byte) bool
}

// lruSessionCache is a ClientSessionCache implementation that uses an LRU
// caching strategy.
type lruSessionCache struct {
	sync.Mutex

	m        map[string]*list.Element
	q        *list.List
	capacity int
}

type lruSessionCacheEntry struct {
	sessionKey string
	state      *ClientSessionState
}

// NewLRUClientSessionCache returns a ClientSessionCache with the given
// capacity that uses an LRU strategy. If capacity is < 1, a default capacity
// is used instead.
func NewLRUClientSessionCache(capacity int) ClientSessionCache {
	const defaultSessionCacheCapacity = 64

	if capacity < 1 {
		capacity = defaultSessionCacheCapacity
	}
	return &lruSessionCache{
		m:        make(map[string]*list.Element),
		q:        list.New(),
		capacity: capacity,
	}
}

// Put adds the provided (sessionKey, cs) pair to the cache.
func (c *lruSessionCache) Put(sessionKey string, cs *ClientSessionState) {
	c.Lock()
	defer c.Unlock()

	if elem, ok := c.m[sessionKey]; ok {
		entry := elem.Value.(*lruSessionCacheEntry)
		entry.state = cs
		c.q.MoveToFront(elem)
		return
	}

	if c.q.Len() < c.capacity {
		entry := &lruSessionCacheEntry{sessionKey, cs}
		c.m[sessionKey] = c.q.PushFront(entry)
		return
	}

	elem := c.q.Back()
	entry := elem.Value.(*lruSessionCacheEntry)
	delete(c.m, entry.sessionKey)
	entry.sessionKey = sessionKey
	entry.state = cs
	c.q.MoveToFront(elem)
	c.m[sessionKey] = elem
}

// Get returns the ClientSessionState value associated with a given key. It
// returns (nil, false) if no value is found.
func (c *lruSessionCache) Get(sessionKey string) (*ClientSessionState, bool) {
	c.Lock()
	defer c.Unlock()

	if elem, ok := c.m[sessionKey]; ok {
		c.q.MoveToFront(elem)
		return elem.Value.(*lruSessionCacheEntry).state, true
	}
	return nil, false
}

// TODO(jsing): Make these available to both crypto/x509 and crypto/tls.
type dsaSignature struct {
	R, S *big.Int
}

type ecdsaSignature dsaSignature

var emptyConfig Config = Config{InsecureSkipVerify: true}

func defaultConfig() *Config {
	return &emptyConfig
}

var (
	once                   sync.Once
	varDefaultCipherSuites []uint16
)

func defaultCipherSuites() []uint16 {
	once.Do(initDefaultCipherSuites)
	return varDefaultCipherSuites
}

func initDefaultCipherSuites() {
	varDefaultCipherSuites = make([]uint16, len(stdlibCipherSuites))
	for i, suite := range stdlibCipherSuites {
		varDefaultCipherSuites[i] = suite.id
	}
}

func unexpectedMessageError(wanted, got interface{}) error {
	return fmt.Errorf("tls: received unexpected handshake message of type %T when waiting for %T", got, wanted)
}

func isSupportedSignatureAndHash(sigHash signatureAndHash, sigHashes []signatureAndHash) bool {
	for _, s := range sigHashes {
		if s == sigHash {
			return true
		}
	}
	return false
}
