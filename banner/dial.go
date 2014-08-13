package banner

import (
	"net"
	"time"
)

type Dialer struct {
	Deadline time.Time
	Timeout time.Duration
	LocalAddr net.Addr
	DualStack bool
	KeepAlive time.Duration
}

func (d *Dialer) Dial(network, address string) (*Conn, error) {
	c := &Conn{operations: make([]ConnectionOperation, 0, 8)}
	netDialer := net.Dialer {
		Deadline: d.Deadline,
		Timeout: d.Timeout,
		LocalAddr: d.LocalAddr,
		KeepAlive: d.KeepAlive,
	}
	var err error
	c.conn, err = netDialer.Dial(network, address)
	cs := connectState {
		protocol: network,
		remoteHost: address,
		err: err,
	}
	c.operations = append(c.operations, &cs)
	return c, err
}
