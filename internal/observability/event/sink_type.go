package event

import (
	"fmt"

	"github.com/hashicorp/boundary/internal/errors"
)

const (
	StderrSink SinkType = "stderr" // StderrSink is written to stderr
	FileSink   SinkType = "file"   // FileSink is written to a file
)

type SinkType string // SinkType defines the type of sink in a config stanza (file, stderr)

func (t SinkType) validate() error {
	const op = "event.(SinkType).validate"
	switch t {
	case StderrSink, FileSink:
		return nil
	default:
		return errors.New(errors.InvalidParameter, op, fmt.Sprintf("'%s' is not a valid sink type", t))
	}
}
