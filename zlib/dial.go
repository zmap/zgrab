/*
 * ZGrab Copyright 2015 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
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
	c := &Conn{}
	netDialer := net.Dialer{
		Deadline:  d.Deadline,
		Timeout:   d.Timeout,
		LocalAddr: d.LocalAddr,
		KeepAlive: d.KeepAlive,
	}
	var err error
	c.conn, err = netDialer.Dial(network, address)
	return c, err
}
