package event

import (
	"fmt"
)

const (
	JSONSinkFormat SinkFormat = "json" // JSONSinkFormat means the event is formatted as JSON
)

type SinkFormat string // SinkFormat defines the formatting for a sink in a config file stanza (json)

func (f SinkFormat) Validate() error {
	const op = "event.(SinkFormat).Validate"
	switch f {
	case JSONSinkFormat:
		return nil
	default:
		return fmt.Errorf("%s: '%s' is not a valid sink format: %w", op, f, ErrInvalidParameter)
	}
}
