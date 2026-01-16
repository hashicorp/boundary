// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package event

import (
	"context"
	"fmt"
	"io"
	"log"
	"sync"

	"github.com/hashicorp/go-hclog"
)

// HclogLoggerAdapter is used to provide an hclog-style interface to code that
// cannot natively handle eventing. Currently, all log lines are written as
// system events. Note that this is not meant for high throughput; some
// potential optimizations (such as using atomic values for name and such) are
// not current implemented. Additionally, some functions (such as fetching a
// stdlib logger/writer) are simply not supported right now.
type HclogLoggerAdapter struct {
	eventCtx context.Context
	l        *sync.RWMutex
	level    hclog.Level
	name     string
	withArgs []any
}

// Ensure that we are implementing Logger
var _ hclog.Logger = (*HclogLoggerAdapter)(nil)

// NewHclogLogger creates a new hclog.Logger-compatible implementation that
// outputs to events
func NewHclogLogger(ctx context.Context, e *Eventer, opt ...Option) (hclog.Logger, error) {
	const op = "event.HclogLogger"
	eventCtx, err := NewEventerContext(ctx, e)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	opts := getOpts(opt...)
	return &HclogLoggerAdapter{
		eventCtx: eventCtx,
		l:        new(sync.RWMutex),
		level:    opts.withHclogLevel,
	}, nil
}

// Args are alternating key, val pairs
// keys must be strings
// vals can be any type, but display is implementation specific
// Emit a message and key/value pairs at a provided log level
func (h *HclogLoggerAdapter) Log(level hclog.Level, msg string, args ...any) {
	switch {
	case h.level == hclog.NoLevel: // If logger is not set to any level, accept it
	case h.level <= level: // Otherwise if logger is same or more verbose, accept
	default:
		return
	}
	h.writeEvent("", msg, args)
}

// Emit a message and key/value pairs at the TRACE level
func (h *HclogLoggerAdapter) Trace(msg string, args ...any) {
	if h.level > hclog.Trace {
		return
	}
	h.writeEvent("", msg, args)
}

// Emit a message and key/value pairs at the DEBUG level
func (h *HclogLoggerAdapter) Debug(msg string, args ...any) {
	if h.level > hclog.Debug {
		return
	}
	h.writeEvent("", msg, args)
}

// Emit a message and key/value pairs at the INFO level
func (h *HclogLoggerAdapter) Info(msg string, args ...any) {
	if h.level > hclog.Info {
		return
	}
	h.writeEvent("", msg, args)
}

// Emit a message and key/value pairs at the WARN level
func (h *HclogLoggerAdapter) Warn(msg string, args ...any) {
	if h.level > hclog.Warn {
		return
	}
	h.writeEvent("", msg, args)
}

// Emit a message and key/value pairs at the ERROR level
func (h *HclogLoggerAdapter) Error(msg string, args ...any) {
	if h.level > hclog.Error {
		return
	}
	h.writeEvent("", msg, args)
}

func (h *HclogLoggerAdapter) writeEvent(caller Op, msg string, args []any) {
	h.l.RLock()
	defer h.l.RUnlock()
	var allArgs []any
	if len(h.withArgs)+len(args) > 0 {
		allArgs = append(h.withArgs, args...)
	}
	if h.name != "" {
		allArgs = append(allArgs, "@original-log-name", h.name)
	}
	allArgs = append(allArgs, "@original-log-level", h.level.String())
	WriteSysEvent(h.eventCtx, "", msg, allArgs...)
}

// Indicate if TRACE logs would be emitted. This and the other Is* guards
// are used to elide expensive logging code based on the current level.
func (h *HclogLoggerAdapter) IsTrace() bool {
	return h.level <= hclog.Trace
}

// Indicate if DEBUG logs would be emitted. This and the other Is* guards
func (h *HclogLoggerAdapter) IsDebug() bool {
	return h.level <= hclog.Debug
}

// Indicate if INFO logs would be emitted. This and the other Is* guards
func (h *HclogLoggerAdapter) IsInfo() bool {
	return h.level <= hclog.Info
}

// Indicate if WARN logs would be emitted. This and the other Is* guards
func (h *HclogLoggerAdapter) IsWarn() bool {
	return h.level <= hclog.Warn
}

// Indicate if ERROR logs would be emitted. This and the other Is* guards
func (h *HclogLoggerAdapter) IsError() bool {
	return h.level <= hclog.Error
}

// ImpliedArgs returns With key/value pairs
func (h *HclogLoggerAdapter) ImpliedArgs() []any {
	return h.withArgs
}

// Creates a sublogger that will always have the given key/value pairs
func (h *HclogLoggerAdapter) With(args ...any) hclog.Logger {
	h.l.Lock()
	defer h.l.Unlock()
	newArgs := args
	if len(h.withArgs) > 0 {
		newArgs = make([]any, len(h.withArgs), len(h.withArgs)+len(args))
		copy(newArgs, h.withArgs)
		newArgs = append(newArgs, args...)
	}
	return &HclogLoggerAdapter{
		eventCtx: h.eventCtx,
		l:        new(sync.RWMutex),
		level:    h.level,
		name:     h.name,
		withArgs: newArgs,
	}
}

// Returns the Name of the logger
func (h *HclogLoggerAdapter) Name() string {
	h.l.RLock()
	defer h.l.RUnlock()
	return h.name
}

// Create a logger that will prepend the name string on the front of all messages.
// If the logger already has a name, the new value will be appended to the current
// name. That way, a major subsystem can use this to decorate all it's own logs
// without losing context.
func (h *HclogLoggerAdapter) Named(name string) hclog.Logger {
	h.l.Lock()
	defer h.l.Unlock()
	var newArgs []any
	if len(h.withArgs) > 0 {
		newArgs = make([]any, len(h.withArgs))
		copy(newArgs, h.withArgs)
	}

	newName := name
	if h.name != "" {
		newName = fmt.Sprintf("%s.%s", h.name, name)
	}

	return &HclogLoggerAdapter{
		eventCtx: h.eventCtx,
		l:        new(sync.RWMutex),
		level:    h.level,
		name:     newName,
		withArgs: newArgs,
	}
}

// Create a logger that will prepend the name string on the front of all messages.
// This sets the name of the logger to the value directly, unlike Named which honor
// the current name as well.
func (h *HclogLoggerAdapter) ResetNamed(name string) hclog.Logger {
	h.l.Lock()
	defer h.l.Unlock()
	var newArgs []any
	if len(h.withArgs) > 0 {
		newArgs = make([]any, len(h.withArgs))
		copy(newArgs, h.withArgs)
	}
	return &HclogLoggerAdapter{
		eventCtx: h.eventCtx,
		l:        new(sync.RWMutex),
		level:    h.level,
		name:     name,
		withArgs: newArgs,
	}
}

// GetLevel returns the current level
func (h *HclogLoggerAdapter) GetLevel() hclog.Level {
	return h.level
}

// Updates the level. This should affect all related loggers as well,
// unless they were created with IndependentLevels. If an
// implementation cannot update the level on the fly, it should no-op.
//
// This implementation is a no-op currently.
func (h *HclogLoggerAdapter) SetLevel(_ hclog.Level) {}

// Return a value that conforms to the stdlib log.Logger interface
//
// This implementation does not currently support this and returns nil.
func (h *HclogLoggerAdapter) StandardLogger(opts *hclog.StandardLoggerOptions) *log.Logger {
	return nil
}

// Return a value that conforms to io.Writer, which can be passed into log.SetOutput()
//
// This implementation does not currently support this and returns nil.
func (h *HclogLoggerAdapter) StandardWriter(opts *hclog.StandardLoggerOptions) io.Writer {
	return nil
}
