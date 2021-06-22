package event

import (
	"fmt"
)

const (
	JSONSinkFormat SinkFormat = "json" // JSONSinkFormat means the event is formatted as JSON
)

type SinkFormat string // SinkFormat defines the formatting for a sink in a config file stanza (json)

func (f SinkFormat) validate() error {
	const op = "event.(SinkFormat).validate"
	switch f {
	case JSONSinkFormat:
		return nil
	default:
		return fmt.Errorf("%s: '%s' is not a valid sink format: %w", op, f, ErrInvalidParameter)
	}
}
