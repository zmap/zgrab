/*
 * ZGrab Copyright 2015 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

package zlib

import (
	"testing"

	. "gopkg.in/check.v1"
)

func TestZTLSEventSuite(t *testing.T) { TestingT(t) }

type ZTLSEventSuite struct{}

var _ = Suite(&ZTLSEventSuite{})

func (s *ZTLSEventSuite) TestTLSTypeName(c *C) {
	c.Check(TLSHandshakeEventType.TypeName, Equals, CONNECTION_EVENT_TLS_NAME)
	t, err := EventTypeFromName(CONNECTION_EVENT_TLS_NAME)
	c.Check(err, IsNil)
	c.Check(t.TypeName, Equals, TLSHandshakeEventType.TypeName)
}
