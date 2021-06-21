package event

import (
	"fmt"

	"github.com/hashicorp/boundary/internal/errors"
)

// EventerConfig supplies all the configuration needed to create/config an Eventer.
type EventerConfig struct {
	AuditEnabled        bool         // AuditEnabled specifies if audit events should be emitted.
	ObservationsEnabled bool         // ObservationsEnabled specifies if observation events should be emitted.
	Sinks               []SinkConfig // Sinks are all the configured sinks
}

// Validate will Validate the config. BTW, a config isn't required to have any
// sinks to be valid.
func (c *EventerConfig) Validate() error {
	const op = "event.(EventerConfig).validate"
	for i, s := range c.Sinks {
		if err := s.validate(); err != nil {
			return errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("sink %d is invalid", i)))
		}
	}
	return nil
}
