// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package base

import (
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/event"
	"github.com/hashicorp/go-bexpr"
)

// EventFlags represent the cmd flags supported overriding the configured or
// default event configuration
type EventFlags struct {
	Format              event.SinkFormat
	AuditEnabled        *bool
	ObservationsEnabled *bool
	SysEventsEnabled    *bool
	TelemetryEnabled    *bool
	AllowFilters        []string
	DenyFilters         []string
}

// Validate simply validates the flags
func (ef *EventFlags) Validate() error {
	if ef != nil {
		if err := ef.Format.Validate(); err != nil {
			return err
		}
		for i, f := range ef.AllowFilters {
			_, err := bexpr.CreateEvaluator(f)
			if err != nil {
				return fmt.Errorf("invalid allow filter '%s': %w", ef.AllowFilters[i], err)
			}
		}
		for i, f := range ef.DenyFilters {
			_, err := bexpr.CreateEvaluator(f)
			if err != nil {
				return fmt.Errorf("invalid deny filter '%s': %w", ef.DenyFilters[i], err)
			}
		}
	}

	return nil
}

type ComposedOfEventArgs struct {
	Format       string
	Observations string
	Audit        string
	SysEvents    string
	Telemetry    string
	Allow        []string
	Deny         []string
}

// NewEventFlags will create a new EventFlags based on the ComposedOfEventArgs
// which should be populated with command flags which have already been "parsed"
func NewEventFlags(defaultFormat event.SinkFormat, c ComposedOfEventArgs) (*EventFlags, error) {
	const op = "base.NewEventFlags"
	if defaultFormat == "" {
		return nil, fmt.Errorf("%s: missing default sink format", op)
	}
	setTrue := true
	setFalse := false
	f := &EventFlags{
		Format: defaultFormat,
	}
	if c.Format != "" {
		f.Format = event.SinkFormat(c.Format)
	}
	switch strings.ToLower(c.Observations) {
	case "true":
		f.ObservationsEnabled = &setTrue
	case "false":
		f.ObservationsEnabled = &setFalse
	}
	switch strings.ToLower(c.Telemetry) {
	case "true":
		f.TelemetryEnabled = &setTrue
	case "false":
		f.TelemetryEnabled = &setFalse
	}
	switch strings.ToLower(c.Audit) {
	case "true":
		f.AuditEnabled = &setTrue
	case "false":
		f.AuditEnabled = &setFalse
	}
	switch strings.ToLower(c.SysEvents) {
	case "true":
		f.SysEventsEnabled = &setTrue
	case "false":
		f.SysEventsEnabled = &setFalse
	}

	if len(c.Allow) > 0 {
		f.AllowFilters = c.Allow
	}
	if len(c.Deny) > 0 {
		f.DenyFilters = c.Deny
	}
	if err := f.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return f, nil
}
