// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package logging

import (
	"fmt"
	"io"
	"os"
	"strings"

	log "github.com/hashicorp/go-hclog"
)

type LogFormat int

const (
	UnspecifiedFormat LogFormat = iota
	StandardFormat
	JSONFormat
)

// Stringer implementation
func (l LogFormat) String() string {
	switch l {
	case UnspecifiedFormat:
		return "unspecified"
	case StandardFormat:
		return "standard"
	case JSONFormat:
		return "json"
	}

	// unreachable
	return "unknown"
}

// NewLogger creates a new logger with the specified level and a formatter
func NewLogger(level log.Level) log.Logger {
	return NewLoggerWithWriter(log.DefaultOutput, level)
}

// NewLoggerWithWriter creates a new logger with the specified level and
// writer and a formatter
func NewLoggerWithWriter(w io.Writer, level log.Level) log.Logger {
	opts := &log.LoggerOptions{
		Level:      level,
		Output:     w,
		JSONFormat: ParseEnvLogFormat() == JSONFormat,
	}
	return log.New(opts)
}

// ParseLogFormat parses the log format from the provided string.
func ParseLogFormat(format string) (LogFormat, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "":
		return UnspecifiedFormat, nil
	case "standard":
		return StandardFormat, nil
	case "json":
		return JSONFormat, nil
	default:
		return UnspecifiedFormat, fmt.Errorf("Unknown log format: %s", format)
	}
}

// ParseEnvLogFormat parses the log format from an environment variable.
func ParseEnvLogFormat() LogFormat {
	logFormat := os.Getenv("BOUNDARY_LOG_FORMAT")
	switch strings.ToLower(logFormat) {
	case "json":
		return JSONFormat
	case "standard":
		return StandardFormat
	default:
		return UnspecifiedFormat
	}
}
