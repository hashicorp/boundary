// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

// Package asciicast defines structs to ease the creation of asciicast files.
// See: https://github.com/asciinema/asciinema/blob/develop/doc/asciicast-v2.md
package asciicast

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/hashicorp/boundary/internal/bsr"
)

const (
	// Version is the file format version.
	Version uint32 = 2
)

// Minimums for width and height to always display a reasonable terminal.
// This is only the initial terminal size, so it does not seem to have any
// real impact on playback.
const (
	DefaultWidth  uint32 = 80
	DefaultHeight uint32 = 24
)

// Sane defaults for the Env section of the Header.
const (
	DefaultShell = "/bin/bash"
	DefaultTerm  = "xterm"
)

// Time is a time.Time that will be marshaled to a unix timestamp as an integer.
type Time time.Time

// MarshalJSON implements the Marshaler interface.
// It will represent the time as a unix timestamp integer.
func (t Time) MarshalJSON() ([]byte, error) {
	return []byte(strconv.FormatInt(time.Time(t).Unix(), 10)), nil
}

func (t *Time) UnmarshalJSON(b []byte) (err error) {
	q, err := strconv.ParseInt(string(b), 10, 64)
	if err != nil {
		return err
	}
	*(*time.Time)(t) = time.Unix(q, 0)
	return err
}

// HeaderEnv is the env section of the header line.
type HeaderEnv struct {
	Shell string `json:"SHELL,omitempty"`
	Term  string `json:"TERM,omitempty"`
}

// Header is the first line of an asciicast.
// https://github.com/asciinema/asciinema/blob/develop/doc/asciicast-v2.md#header
type Header struct {
	Version   uint32    `json:"version"`
	Width     uint32    `json:"width"`
	Height    uint32    `json:"height"`
	Timestamp Time      `json:"timestamp"`
	Env       HeaderEnv `json:"env"`
}

// NewHeader creates a Header.
func NewHeader() *Header {
	return &Header{
		Version: Version,
		Width:   DefaultWidth,
		Height:  DefaultHeight,
		Env: HeaderEnv{
			Shell: DefaultShell,
			Term:  DefaultTerm,
		},
	}
}

// EventType defines the type of an event in the event stream.
// https://github.com/asciinema/asciinema/blob/develop/doc/asciicast-v2.md#supported-event-types
type EventType string

// Valid event types
// https://github.com/asciinema/asciinema/blob/develop/doc/asciicast-v2.md#supported-event-types
const (
	Output EventType = `o`
	Input  EventType = `i`
	Marker EventType = `m`
)

// ValidEventType checks if a given EventType is valid.
func ValidEventType(t EventType) bool {
	switch t {
	case Output, Input, Marker:
		return true
	}
	return false
}

// Event is an element in the event stream.
// https://github.com/asciinema/asciinema/blob/develop/doc/asciicast-v2.md#event-stream
type Event struct {
	Time float64
	Type EventType
	Data []byte
}

// NewEvent creates an Event for the event stream.
func NewEvent(t EventType, ts float64, data []byte) (*Event, error) {
	const op = "asciicast.NewEvent"

	if !ValidEventType(t) {
		return nil, fmt.Errorf("%s: invalid event type %s: %w", op, t, bsr.ErrInvalidParameter)
	}

	return &Event{
		Time: ts,
		Type: t,
		Data: data,
	}, nil
}

// MarshalJSON implements the Marshaler interface.
func (e *Event) MarshalJSON() ([]byte, error) {
	line := []any{
		e.Time,
		string(e.Type),
		string(e.Data),
	}
	return json.Marshal(line)
}
