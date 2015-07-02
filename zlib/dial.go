/*
 * ZGrab Copyright 2015 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

package zlib

import (
	"net"
	"time"
)

type Dialer struct {
	Deadline  time.Time
	Timeout   time.Duration
	LocalAddr net.Addr
	DualStack bool
	KeepAlive time.Duration
}

func (d *Dialer) Dial(network, address string) (*Conn, error) {
	c := &Conn{operations: make([]ConnectionEvent, 0, 8)}
	netDialer := net.Dialer{
		Deadline:  d.Deadline,
		Timeout:   d.Timeout,
		LocalAddr: d.LocalAddr,
		KeepAlive: d.KeepAlive,
	}
	var err error
	c.conn, err = netDialer.Dial(network, address)
	event := ConnectionEvent{
		Data:  &ConnectEvent{},
		Error: err,
	}
	c.operations = append(c.operations, event)
	return c, err
}
