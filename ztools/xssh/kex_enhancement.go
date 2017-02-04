package xssh

import (
	"crypto"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/big"

	ztoolsKeys "github.com/zmap/zgrab/ztools/keys"
)

type dhGEXSHA1JsonLog struct {
	DHParams        *ztoolsKeys.DHParams  `json:"parameters,omitempty"`
	ServerHostKey   *ServerHostKeyJsonLog `json:"server_host_key,omitempty"`
	ServerSignature []byte                `json:"server_signature,omitempty"`
}

type dhGEXSHA1 struct {
	g, p    *big.Int
	JsonLog *dhGEXSHA1JsonLog
}

func (gex *dhGEXSHA1) GetNew(_ string) kexAlgorithm {
	return new(dhGEXSHA1)
}

func (gex *dhGEXSHA1) MarshalJSON() ([]byte, error) {
	return json.Marshal(gex.JsonLog)
}

func (gex *dhGEXSHA1) diffieHellman(theirPublic, myPrivate *big.Int) (*big.Int, error) {
	if theirPublic.Sign() <= 0 || theirPublic.Cmp(gex.p) >= 0 {
		return nil, fmt.Errorf("ssh: DH parameter out of bounds")
	}
	return new(big.Int).Exp(theirPublic, myPrivate, gex.p), nil
}

func (gex *dhGEXSHA1) Client(c packetConn, randSource io.Reader, magics *handshakeMagics) (*kexResult, error) {
	gex.JsonLog = new(dhGEXSHA1JsonLog)
	gex.JsonLog.DHParams = new(ztoolsKeys.DHParams)

	hashFunc := crypto.SHA1

	// Send GexRequest
	kexDHGexRequest := kexDHGexRequestMsg{
		MinBits:      uint32(pkgConfig.GEXMinBits),
		PreferedBits: uint32(pkgConfig.GEXPreferredBits),
		MaxBits:      uint32(pkgConfig.GEXMaxBits),
	}
	if err := c.writePacket(Marshal(&kexDHGexRequest)); err != nil {
		return nil, err
	}

	// *Receive GexGroup*
	packet, err := c.readPacket()
	if err != nil {
		return nil, err
	}

	var kexDHGexGroup kexDHGexGroupMsg
	if err = Unmarshal(packet, &kexDHGexGroup); err != nil {
		return nil, err
	}

	gex.JsonLog.DHParams.Generator = kexDHGexGroup.G
	gex.JsonLog.DHParams.Prime = kexDHGexGroup.P

	// reject if p's bit length < pkgConfig.GEXMinBits or > pkgConfig.GEXMaxBits
	if kexDHGexGroup.P.BitLen() < pkgConfig.GEXMinBits || kexDHGexGroup.P.BitLen() > pkgConfig.GEXMaxBits {
		return nil, fmt.Errorf("Server-generated gex p (dont't ask) is out of range (%d bits)", kexDHGexGroup.P.BitLen())
	}

	gex.p = kexDHGexGroup.P
	gex.g = kexDHGexGroup.G

	// *Send GexInit
	x, err := rand.Int(randSource, gex.p)
	if err != nil {
		return nil, err
	}
	X := new(big.Int).Exp(gex.g, x, gex.p)
	kexDHGexInit := kexDHGexInitMsg{
		X: X,
	}

	if pkgConfig.Verbose {
		gex.JsonLog.DHParams.ClientPublic = X
		gex.JsonLog.DHParams.ClientPrivate = x
	}

	if err := c.writePacket(Marshal(&kexDHGexInit)); err != nil {
		return nil, err
	}

	// Receive GexReply
	packet, err = c.readPacket()
	if err != nil {
		return nil, err
	}

	var kexDHGexReply kexDHGexReplyMsg
	if err = Unmarshal(packet, &kexDHGexReply); err != nil {
		return nil, err
	}

	gex.JsonLog.DHParams.ServerPublic = kexDHGexReply.Y
	gex.JsonLog.ServerHostKey = LogServerHostKey(kexDHGexReply.HostKey)
	gex.JsonLog.ServerSignature = kexDHGexReply.Signature[:]

	kInt, err := gex.diffieHellman(kexDHGexReply.Y, x)
	if err != nil {
		return nil, err
	}

	h := hashFunc.New()
	magics.write(h)
	writeString(h, kexDHGexReply.HostKey)
	binary.Write(h, binary.BigEndian, uint32(pkgConfig.GEXMinBits))
	binary.Write(h, binary.BigEndian, uint32(pkgConfig.GEXPreferredBits))
	binary.Write(h, binary.BigEndian, uint32(pkgConfig.GEXMaxBits))
	writeInt(h, gex.p)
	writeInt(h, gex.g)
	writeInt(h, X)
	writeInt(h, kexDHGexReply.Y)
	K := make([]byte, intLength(kInt))
	marshalInt(K, kInt)
	h.Write(K)

	return &kexResult{
		H:         h.Sum(nil),
		K:         K,
		HostKey:   kexDHGexReply.HostKey,
		Signature: kexDHGexReply.Signature,
		Hash:      crypto.SHA1,
	}, nil
}

func (gex *dhGEXSHA1) Server(c packetConn, randSource io.Reader, magics *handshakeMagics, priv Signer) (result *kexResult, err error) {
	hashFunc := crypto.SHA1

	// *Receive GexRequest*
	packet, err := c.readPacket()
	if err != nil {
		return
	}
	var kexDHGexRequest kexDHGexRequestMsg
	if err = Unmarshal(packet, &kexDHGexRequest); err != nil {
		return
	}

	// smoosh the user's preferred size into our own limits
	if kexDHGexRequest.PreferedBits > uint32(pkgConfig.GEXMaxBits) {
		kexDHGexRequest.PreferedBits = uint32(pkgConfig.GEXMaxBits)
	}
	if kexDHGexRequest.PreferedBits < uint32(pkgConfig.GEXMinBits) {
		kexDHGexRequest.PreferedBits = uint32(pkgConfig.GEXMinBits)
	}
	// fix min/max if they're inconsistent.  technically, we could just pout
	// and hang up, but there's no harm in giving them the benefit of the
	// doubt and just picking a bitsize for them.
	if kexDHGexRequest.MinBits > kexDHGexRequest.PreferedBits {
		kexDHGexRequest.MinBits = kexDHGexRequest.PreferedBits
	}
	if kexDHGexRequest.MaxBits < kexDHGexRequest.PreferedBits {
		kexDHGexRequest.MaxBits = kexDHGexRequest.PreferedBits
	}

	// *Send GexGroup*
	// generate prime
	// TODO: Not implemented yet, should load primes from /etc/ssh/moduli
	gex.p, _ = new(big.Int).SetString("D1391174233D315398FE2830AC6B2B66BCCD01B0A634899F339B7879F1DB85712E9DC4E4B1C6C8355570C1D2DCB53493DF18175A9C53D1128B592B4C72D97136F5542FEB981CBFE8012FDD30361F288A42BD5EBB08BAB0A5640E1AC48763B2ABD1945FEE36B2D55E1D50A1C86CED9DD141C4E7BE2D32D9B562A0F8E2E927020E91F58B57EB9ACDDA106A59302D7E92AD5F6E851A45FA1CFE86029A0F727F65A8F475F33572E2FDAB6073F0C21B8B54C3823DB2EF068927E5D747498F96361507", 16)
	gex.g = big.NewInt(5)
	kexDHGexGroup := kexDHGexGroupMsg{
		P: gex.p,
		G: gex.g,
	}
	if err := c.writePacket(Marshal(&kexDHGexGroup)); err != nil {
		return nil, err
	}

	// *Receive GexInit
	packet, err = c.readPacket()
	if err != nil {
		return
	}
	var kexDHGexInit kexDHGexInitMsg
	if err = Unmarshal(packet, &kexDHGexInit); err != nil {
		return
	}

	// var maxP = big.NewInt(0)
	// *maxP = *gex.p
	// y, err := rand.Int(randSource, maxP.Add(maxP, big.NewInt(-1)).Div(maxP, big.NewInt(2)))
	// fmt.Println("Server:", maxP.BitLen(), gex.p.BitLen())
	//y, err := rand.Int(randSource, gex.p)
	y, err := rand.Int(randSource, gex.p)
	if err != nil {
		return
	}

	Y := new(big.Int).Exp(gex.g, y, gex.p)
	kInt, err := gex.diffieHellman(kexDHGexInit.X, y)
	if err != nil {
		return nil, err
	}

	hostKeyBytes := priv.PublicKey().Marshal()

	h := hashFunc.New()
	magics.write(h)
	writeString(h, hostKeyBytes)
	binary.Write(h, binary.BigEndian, uint32(pkgConfig.GEXMinBits))
	binary.Write(h, binary.BigEndian, uint32(pkgConfig.GEXPreferredBits))
	binary.Write(h, binary.BigEndian, uint32(pkgConfig.GEXMaxBits))
	writeInt(h, gex.p)
	writeInt(h, gex.g)
	writeInt(h, kexDHGexInit.X)
	writeInt(h, Y)

	K := make([]byte, intLength(kInt))
	marshalInt(K, kInt)
	h.Write(K)

	H := h.Sum(nil)

	// H is already a hash, but the hostkey signing will apply its
	// own key-specific hash algorithm.
	sig, err := signAndMarshal(priv, randSource, H)
	if err != nil {
		return nil, err
	}

	kexDHGexReply := kexDHGexReplyMsg{
		HostKey:   hostKeyBytes,
		Y:         Y,
		Signature: sig,
	}
	packet = Marshal(&kexDHGexReply)

	err = c.writePacket(packet)

	return &kexResult{
		H:         H,
		K:         K,
		HostKey:   hostKeyBytes,
		Signature: sig,
		Hash:      crypto.SHA1,
	}, nil
}
