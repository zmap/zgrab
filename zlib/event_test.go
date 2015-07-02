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

func TestEventSuite(t *testing.T) { TestingT(t) }

type EventSuite struct{}

var _ = Suite(&EventSuite{})

func (s *EventSuite) TestEventTypeFromName(c *C) {
	_, err := EventTypeFromName("does-not-exist")
	c.Check(err, NotNil)
}

func (s *EventSuite) TestConnectEventName(c *C) {
	t, err := EventTypeFromName(CONNECTION_EVENT_CONNECT_NAME)
	c.Check(err, IsNil)
	c.Check(t.TypeName, Equals, CONNECTION_EVENT_CONNECT_NAME)
}
