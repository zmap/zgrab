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
