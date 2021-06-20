package event

import (
	"fmt"

	"github.com/hashicorp/boundary/internal/errors"
)

const (
	JSONSinkFormat SinkFormat = "json" // JSONSinkFormat means the event is formatted as JSON
)

type SinkFormat string // SinkFormat defines the formatting for a sink in a config file stanza (json)

func (f SinkFormat) Validate() error {
	const op = "event.(SinkFormat).validate"
	switch f {
	case JSONSinkFormat:
		return nil
	default:
		return errors.New(errors.InvalidParameter, op, fmt.Sprintf("'%s' is not a valid sink format", f))
	}
}
