// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package event

import (
	"fmt"
)

// EventerConfig supplies all the configuration needed to create/config an Eventer.
type EventerConfig struct {
	AuditEnabled        bool          `hcl:"audit_enabled"`        // AuditEnabled specifies if audit events should be emitted.
	ObservationsEnabled bool          `hcl:"observations_enabled"` // ObservationsEnabled specifies if observation events should be emitted.
	SysEventsEnabled    bool          `hcl:"sysevents_enabled"`    // SysEventsEnabled specifies if sysevents should be emitted.
	TelemetryEnabled    bool          `hcl:"telemetry_enabled"`    // TelemetryEnabled specifies if telemetry events should be emitted.
	Sinks               []*SinkConfig `hcl:"-"`                    // Sinks are all the configured sinks
	ErrorEventsDisabled bool          `hcl:"-"`                    // ErrorEventsDisabled will disable error events from being emitted.  This should only be used to turn off error events in tests.
}

// Validate will Validate the config. A config isn't required to have any
// sinks to be valid.
func (c *EventerConfig) Validate() error {
	const op = "event.(EventerConfig).Validate"
	for i, s := range c.Sinks {
		if err := s.Validate(); err != nil {
			return fmt.Errorf("%s: sink %d is invalid: %w", op, i, err)
		}
	}
	if !c.ObservationsEnabled && c.TelemetryEnabled {
		return fmt.Errorf("%s: telemetry events require observation event to be enabled: %w", op, ErrInvalidParameter)
	}
	return nil
}
