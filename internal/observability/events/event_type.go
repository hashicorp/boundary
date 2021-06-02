package event

import (
	"fmt"

	"github.com/hashicorp/boundary/internal/errors"
)

type Type string

const (
	EveryType       Type = "*"
	ObservationType Type = "observation"
	AuditType       Type = "audit"
	ErrorType       Type = "error"
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
