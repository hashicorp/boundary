package event

import (
	"fmt"

	"github.com/hashicorp/boundary/internal/errors"
)

// Type represents the event's type
type Type string

const (
	EveryType       Type = "*"           // EveryType represents every (all) types of events
	ObservationType Type = "observation" // ObservationType represents observation events
	AuditType       Type = "audit"       // AuditType represents audit events
	ErrorType       Type = "error"       // ErrorType represents error events
)

func (et Type) validate() error {
	const op = "event.(Type).validate"
	switch et {
	case EveryType, ObservationType, AuditType, ErrorType:
		return nil
	default:
		return errors.New(errors.InvalidParameter, op, fmt.Sprintf("'%s' is not a valid event type", et))
	}
}
