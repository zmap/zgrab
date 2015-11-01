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

package zlog

import (
	"testing"

	. "gopkg.in/check.v1"
)

func TestLogger(t *testing.T) { TestingT(t) }

type LoggerSuite struct{}

var _ = Suite(&LoggerSuite{})

// TODO: Actually implement verification

func (s *LoggerSuite) TestPrint(c *C) {
	Error("THIS IS MAGENTA")
	Warn("THIS IS YELLOW")
	Info("THIS IS GREEN")
	Debug("THIS IS BLUE")
	Trace("THIS IS NORMAL")
}

func (s *LoggerSuite) TestPrintf(c *C) {
	Printf(LOG_ERROR, "THIS IS MAGENTA: %d == %d", 1, 1)
}
