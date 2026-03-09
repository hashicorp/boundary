// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package event

import (
	"fmt"
)

const (
	JSONSinkFormat      SinkFormat = "cloudevents-json" // JSONSinkFormat means the event is formatted as JSON
	TextSinkFormat      SinkFormat = "cloudevents-text" // TextSinkFormat means the event is formmatted as text
	TextHclogSinkFormat SinkFormat = "hclog-text"       // TextHclogSinkFormat means the event is formatted as an hclog text entry
	JSONHclogSinkFormat SinkFormat = "hclog-json"       // JSONHclogSinkFormat means the event is formated as an hclog json entry
)

type SinkFormat string // SinkFormat defines the formatting for a sink in a config file stanza (json)

func (f SinkFormat) Validate() error {
	const op = "event.(SinkFormat).Validate"
	switch f {
	case JSONSinkFormat, TextSinkFormat:
		return nil
	case TextHclogSinkFormat, JSONHclogSinkFormat:
		return nil
	default:
		return fmt.Errorf("%s: '%s' is not a valid sink format: %w", op, f, ErrInvalidParameter)
	}
}
