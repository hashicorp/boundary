package event

import (
	"fmt"
)

// EventerConfig supplies all the configuration needed to create/config an Eventer.
type EventerConfig struct {
	AuditDelivery       DeliveryGuarantee // AuditDelivery specifies the delivery guarantees for audit events (enforced or best effort).
	ObservationDelivery DeliveryGuarantee // ObservationDelivery specifies the delivery guarantees for observation events (enforced or best effort).
	AuditEnabled        bool              // AuditEnabled specifies if audit events should be emitted.
	ObservationsEnabled bool              // ObservationsEnabled specifies if observation events should be emitted.
	Sinks               []SinkConfig      // Sinks are all the configured sinks
}

// validate will validate the config. BTW, a config isn't required to have any
// sinks to be valid.
func (c *EventerConfig) validate() error {
	const op = "event.(EventerConfig).validate"

	if err := c.AuditDelivery.validate(); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	if err := c.ObservationDelivery.validate(); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	for i, s := range c.Sinks {
		if err := s.validate(); err != nil {
			return fmt.Errorf("%s: sink %d is invalid: %w", op, i, err)
		}
	}
	return nil
}
