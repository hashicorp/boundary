package event

import (
	"fmt"
)

const (
	StderrSink SinkType = "stderr" // StderrSink is written to stderr
	FileSink   SinkType = "file"   // FileSink is written to a file
)

type SinkType string // SinkType defines the type of sink in a config stanza (file, stderr)

func (t SinkType) Validate() error {
	const op = "event.(SinkType).validate"
	switch t {
	case StderrSink, FileSink:
		return nil
	default:
		return fmt.Errorf("%s: '%s' is not a valid sink type: %w", op, t, ErrInvalidParameter)
	}
}
