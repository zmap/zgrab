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
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

type Logger struct {
	mu     sync.Mutex
	out    io.Writer
	prefix string

	// Color handling
	useColor     bool
	currentColor color
}

type LogLevel uint8
type color []byte

const (
	prefixFormat = "%s [%s] %s: "
)

const (
	LOG_FATAL LogLevel = iota
	LOG_ERROR LogLevel = iota
	LOG_WARN  LogLevel = iota
	LOG_INFO  LogLevel = iota
	LOG_DEBUG LogLevel = iota
	LOG_TRACE LogLevel = iota
)

const (
	colorRed     = "\x1b[31m"
	colorGreen   = "\x1b[32m"
	colorYellow  = "\x1b[33m"
	colorBlue    = "\x1b[34m"
	colorMagenta = "\x1b[35m"
	colorCyan    = "\x1b[36m"
	colorReset   = "\033[0m"
)

var (
	red     color = []byte(colorRed)
	green   color = []byte(colorGreen)
	yellow  color = []byte(colorYellow)
	blue    color = []byte(colorBlue)
	magenta color = []byte(colorMagenta)
	cyan    color = []byte(colorCyan)
	reset   color = []byte(colorReset)
)

var (
	levelNames = []string{"FATAL", "ERROR", "WARN", "INFO", "DEBUG", "TRACE"}
	colors     = []color{red, magenta, yellow, green, blue, reset, reset}
)

var (
	defaultLogger = New(os.Stderr, "log")
)

func (level LogLevel) String() string {
	if level > LOG_TRACE {
		level = LOG_TRACE
	}
	return levelNames[level]
}

func (level LogLevel) Color() color {
	if level > LOG_TRACE {
		level = LOG_TRACE
	}
	return colors[level]
}

func New(out io.Writer, prefix string) *Logger {
	useColor := false
	file, ok := out.(*os.File)
	if ok {
		stats, _ := file.Stat()
		// Check to see if output is a terminal
		if (stats.Mode() & os.ModeCharDevice) != 0 {
			useColor = true
		}
	}
	logger := Logger{
		out:      out,
		prefix:   prefix,
		useColor: useColor,
	}
	return &logger
}

func (logger *Logger) Fatal(v ...interface{}) {
	logger.doPrint(LOG_FATAL, v...)
	os.Exit(1)
}

func (logger *Logger) Fatalf(format string, v ...interface{}) {
	logger.doPrintf(LOG_FATAL, format, v...)
	os.Exit(1)
}

func (logger *Logger) Error(v ...interface{}) {
	logger.doPrint(LOG_ERROR, v...)
}

func (logger *Logger) Errorf(format string, v ...interface{}) {
	logger.doPrintf(LOG_ERROR, format, v...)
}

func (logger *Logger) Warn(v ...interface{}) {
	logger.doPrint(LOG_WARN, v...)
}

func (logger *Logger) Warnf(format string, v ...interface{}) {
	logger.doPrintf(LOG_WARN, format, v...)
}

func (logger *Logger) Info(v ...interface{}) {
	logger.doPrint(LOG_INFO, v...)
}

func (logger *Logger) Infof(format string, v ...interface{}) {
	logger.doPrintf(LOG_INFO, format, v...)
}

func (logger *Logger) Debug(v ...interface{}) {
	logger.doPrint(LOG_DEBUG, v...)
}

func (logger *Logger) Debugf(format string, v ...interface{}) {
	logger.doPrintf(LOG_DEBUG, format, v...)
}

func (logger *Logger) Trace(v ...interface{}) {
	logger.doPrint(LOG_TRACE, v...)
}

func (logger *Logger) Tracef(format string, v ...interface{}) {
	logger.doPrintf(LOG_TRACE, format, v...)
}

func Fatal(v ...interface{}) {
	defaultLogger.Fatal(v...)
}

func Fatalf(format string, v ...interface{}) {
	defaultLogger.Fatalf(format, v...)
}

func Error(v ...interface{}) {
	defaultLogger.Error(v...)
}

func Errorf(format string, v ...interface{}) {
	defaultLogger.Errorf(format, v...)
}

func Warn(v ...interface{}) {
	defaultLogger.Warn(v...)
}

func Warnf(format string, v ...interface{}) {
	defaultLogger.Warnf(format, v...)
}

func Debug(v ...interface{}) {
	defaultLogger.Debug(v...)
}

func Debugf(format string, v ...interface{}) {
	defaultLogger.Debugf(format, v...)
}

func Info(v ...interface{}) {
	defaultLogger.Info(v...)
}

func Infof(format string, v ...interface{}) {
	defaultLogger.Infof(format, v...)
}

func Trace(v ...interface{}) {
	defaultLogger.Trace(v...)
}

func Tracef(format string, v ...interface{}) {
	defaultLogger.Tracef(format, v...)
}

func (logger *Logger) Print(level LogLevel, v ...interface{}) {
	if level > LOG_TRACE {
		level = LOG_TRACE
	}
	logger.doPrint(level, v...)
	if level == LOG_FATAL {
		os.Exit(1)
	}
}

func (logger *Logger) Printf(level LogLevel, format string, v ...interface{}) {
	if level > LOG_TRACE {
		level = LOG_TRACE
	}
	logger.doPrintf(level, format, v...)
	if level == LOG_FATAL {
		os.Exit(1)
	}
}

func Print(level LogLevel, v ...interface{}) {
	defaultLogger.Print(level, v...)
}

func Printf(level LogLevel, format string, v ...interface{}) {
	defaultLogger.Printf(level, format, v...)
}

func (logger *Logger) setColor(c color) {
	logger.currentColor = c
}

func (logger *Logger) clearColor() {
	logger.currentColor = reset
}

func (logger *Logger) doPrint(level LogLevel, v ...interface{}) {
	timestamp := time.Now().Format(time.StampMilli)
	logger.mu.Lock()
	defer logger.mu.Unlock()
	// Handle color output
	if logger.useColor {
		logger.out.Write(colors[level])
		defer logger.out.Write(reset)
	}

	// Write the line out
	fmt.Fprintf(logger.out, prefixFormat, timestamp, level.String(), logger.prefix)
	fmt.Fprint(logger.out, v...)
	logger.out.Write([]byte{'\n'})
}

func (logger *Logger) doPrintf(level LogLevel, format string, v ...interface{}) {
	timestamp := time.Now().Format(time.StampMilli)
	logger.mu.Lock()
	defer logger.mu.Unlock()
	// Handle color
	if logger.useColor {
		logger.out.Write(colors[level])
		defer logger.out.Write(reset)
	}
	// Write the line out
	fmt.Fprintf(logger.out, prefixFormat, timestamp, level.String(), logger.prefix)
	fmt.Fprintf(logger.out, format, v...)
	logger.out.Write([]byte{'\n'})
}
