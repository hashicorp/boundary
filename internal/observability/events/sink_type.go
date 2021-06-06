package event

import (
	"fmt"

	"github.com/hashicorp/boundary/internal/errors"
)

const (
	StdoutSink SinkType = "stdout" // StdoutSink is written to stdout
	FileSink   SinkType = "file"   // FileSink is written to a file
)

type SinkType string // SinkType defines the type of sink in a config stanza (file, stdout)

func (t SinkType) validate() error {
	const op = "event.(SinkType).validate"
	switch t {
	case StdoutSink, FileSink:
		return nil
	default:
		return errors.New(errors.InvalidParameter, op, fmt.Sprintf("'%s' is not a valid sink type", t))
	}
}
