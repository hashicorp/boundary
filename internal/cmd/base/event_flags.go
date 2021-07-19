package base

import "github.com/hashicorp/boundary/internal/observability/event"

// EventFlags represent the cmd flags supported overriding the configured or
// default event configuration
type EventFlags struct {
	Format              event.SinkFormat
	AuditEnabled        *bool
	ObservationsEnabled *bool
	SysEventsEnabled    *bool
}

// Validate simply validates the flags
func (ef *EventFlags) Validate() error {
	if ef != nil {
		if err := ef.Format.Validate(); err != nil {
			return err
		}
	}
	return nil
}
