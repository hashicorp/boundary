package event

import (
	"fmt"
)

const (
	JSONSinkFormat SinkFormat = "cloudevents-json" // JSONSinkFormat means the event is formatted as JSON
	TextSinkFormat SinkFormat = "cloudevents-text" // TextSinkFormat means the event is formmatted as text
)

type SinkFormat string // SinkFormat defines the formatting for a sink in a config file stanza (json)

func (f SinkFormat) Validate() error {
	const op = "event.(SinkFormat).Validate"
	switch f {
	case JSONSinkFormat, TextSinkFormat:
		return nil
	default:
		return fmt.Errorf("%s: '%s' is not a valid sink format: %w", op, f, ErrInvalidParameter)
	}
}
