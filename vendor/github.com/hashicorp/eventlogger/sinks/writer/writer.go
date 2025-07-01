// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package writer

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"

	"github.com/hashicorp/eventlogger"
)

// Sink writes the []byte respresentation of an Event to an io.Writer as a
// string.  Sink allows you to define sinks for any io.Writer which
// includes os.Stdout and os.Stderr
type Sink struct {
	l sync.RWMutex

	// Format specifies the format the []byte representation is formatted in
	// Defaults to JSONFormat
	Format string

	// Writer is the io.Writer used when writing Events
	Writer io.Writer
}

// Reopen does nothing for this type of Sink.  They cannot be rotated.
func (fs *Sink) Reopen() error { return nil }

// Type defines the Sink as a NodeTypeSink
func (fs *Sink) Type() eventlogger.NodeType {
	return eventlogger.NodeTypeSink
}

// Process will Write the event to the Sink
func (fs *Sink) Process(ctx context.Context, e *eventlogger.Event) (*eventlogger.Event, error) {
	if fs.Writer == nil {
		return nil, errors.New("sink writer is nil")
	}
	if e == nil {
		return nil, errors.New("event is nil")
	}

	format := fs.Format
	if fs.Format == "" {
		format = eventlogger.JSONFormat
	}
	val, ok := e.Format(format)
	if !ok {
		return nil, errors.New("event was not marshaled")
	}
	reader := bytes.NewReader(val)

	fs.l.Lock()
	defer fs.l.Unlock()
	if _, err := reader.WriteTo(fs.Writer); err != nil {
		return nil, err
	}

	// Sinks are leafs, so do not return the event, since nothing more can
	// happen to it downstream.
	return nil, nil
}
