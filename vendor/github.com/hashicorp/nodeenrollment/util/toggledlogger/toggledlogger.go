// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package toggledlogger

import (
	"io"
	"log"
	"sync/atomic"

	"github.com/hashicorp/go-hclog"
)

// ToggledLogger is used to provide an hclog-style interface that can be turned
// on/off at will. This is useful for providing a logger to this package where
// you may only want internal authentication logging to happen in specific
// debugging scenarios.
//
// When using With and Named and such, the returned logger will share the
// enabled state of this logger. If this is not what you want, create a new
// ToggledLogger with the result of With or Name directly called on the
// underlying logger.
type ToggledLogger struct {
	enabled    *atomic.Bool
	underlying hclog.Logger
}

// Ensure that we are implementing Logger
var _ hclog.Logger = (*ToggledLogger)(nil)

// NewToggledLogger creates a new logger, without performing nil checking on the
// underlying logger.
//
// If enabled is provided, it is used when checking whether to log, which can be
// useful for tying lifecycle of enablement of this logger to some other
// process. If nil, an internal value will be created and used.
func NewToggledLogger(underlying hclog.Logger, enabled *atomic.Bool) hclog.Logger {
	tl := &ToggledLogger{
		underlying: underlying,
		enabled:    enabled,
	}
	if enabled == nil {
		tl.enabled = new(atomic.Bool)
	}
	return tl
}

// SetEnabled sets the enabled state of the logger
func (tl *ToggledLogger) SetEnabled(enabled bool) {
	tl.enabled.Store(enabled)
}

// Log logs a message at the given level, if this logger is enabled
func (tl *ToggledLogger) Log(level hclog.Level, msg string, args ...any) {
	if tl.enabled.Load() {
		tl.underlying.Log(level, msg, args...)
	}
}

// Trace logs a message at the Trace level, if this logger is enabled
func (tl *ToggledLogger) Trace(msg string, args ...any) {
	if tl.enabled.Load() {
		tl.underlying.Trace(msg, args...)
	}
}

// Debug logs a message at the Debug level, if this logger is enabled
func (tl *ToggledLogger) Debug(msg string, args ...any) {
	if tl.enabled.Load() {
		tl.underlying.Debug(msg, args...)
	}
}

// Info logs a message at the Info level, if this logger is enabled
func (tl *ToggledLogger) Info(msg string, args ...any) {
	if tl.enabled.Load() {
		tl.underlying.Info(msg, args...)
	}
}

// Warn logs a message at the Warn level, if this logger is enabled
func (tl *ToggledLogger) Warn(msg string, args ...any) {
	if tl.enabled.Load() {
		tl.underlying.Warn(msg, args...)
	}
}

// Error logs a message at the Error level, if this logger is enabled
func (tl *ToggledLogger) Error(msg string, args ...any) {
	if tl.enabled.Load() {
		tl.underlying.Error(msg, args...)
	}
}

// IsTrace returns the call of the same name on the underlying logger
func (tl *ToggledLogger) IsTrace() bool {
	return tl.underlying.IsTrace()
}

// IsDebug returns the call of the same name on the underlying logger
func (tl *ToggledLogger) IsDebug() bool {
	return tl.underlying.IsDebug()
}

// IsInfo returns the call of the same name on the underlying logger
func (tl *ToggledLogger) IsInfo() bool {
	return tl.underlying.IsInfo()
}

// IsWarn returns the call of the same name on the underlying logger
func (tl *ToggledLogger) IsWarn() bool {
	return tl.underlying.IsWarn()
}

// IsError returns the call of the same name on the underlying logger
func (tl *ToggledLogger) IsError() bool {
	return tl.underlying.IsError()
}

// ImpliedArgs returns the implied args of the underlying logger
func (tl *ToggledLogger) ImpliedArgs() []any {
	return tl.underlying.ImpliedArgs()
}

// With returns the underlying logger with With called, but shares this logger's
// enabled state
func (tl *ToggledLogger) With(args ...any) hclog.Logger {
	return &ToggledLogger{
		underlying: tl.underlying.With(args...),
		enabled:    tl.enabled,
	}
}

func (tl *ToggledLogger) Name() string {
	return tl.underlying.Name()
}

// Named returns the underlying logger with Named called, but shares this
// logger's enabled state
func (tl *ToggledLogger) Named(name string) hclog.Logger {
	return &ToggledLogger{
		underlying: tl.underlying.Named(name),
		enabled:    tl.enabled,
	}
}

// ResetNamed returns the underlying logger with ResetNamed called, but shares
// this logger's enabled state
func (tl *ToggledLogger) ResetNamed(name string) hclog.Logger {
	return &ToggledLogger{
		underlying: tl.underlying.ResetNamed(name),
		enabled:    tl.enabled,
	}
}

// GetLevel returns the current level
func (tl *ToggledLogger) GetLevel() hclog.Level {
	return tl.underlying.GetLevel()
}

// SetLevel sets the level of the underlying logger
func (tl *ToggledLogger) SetLevel(level hclog.Level) {
	tl.underlying.SetLevel(level)
}

// StandardLogger is currently not supported and returns nil
func (tl *ToggledLogger) StandardLogger(opts *hclog.StandardLoggerOptions) *log.Logger {
	return nil
}

// StandardWriter is currently not supported and returns nil
func (tl *ToggledLogger) StandardWriter(opts *hclog.StandardLoggerOptions) io.Writer {
	return nil
}
