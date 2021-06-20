package event

import (
	"time"

	"github.com/hashicorp/boundary/internal/errors"
)

// SinkConfig defines the configuration for a Eventer sink
type SinkConfig struct {
	Name           string        // Name defines a name for the sink.
	EventTypes     []Type        // EventTypes defines a list of event types that will be sent to the sink. See the docs for EventTypes for a list of accepted values.
	SinkType       SinkType      // SinkType defines the type of sink (StdoutSink or FileSink)
	Format         SinkFormat    // Format defines the format for the sink (JSONSinkFormat)
	Path           string        // Path defines the file path for the sink
	FileName       string        // FileName defines the file name for the sink
	RotateBytes    int           // RotateByes defines the number of bytes that should trigger rotation of a FileSink
	RotateDuration time.Duration // RotateDuration defines how often a FileSink should be rotated
	RotateMaxFiles int           // RotateMaxFiles defines how may historical rotated files should be kept for a FileSink
}

func (sc *SinkConfig) validate() error {
	const op = "event.(SinkConfig).validate"
	if err := sc.SinkType.validate(); err != nil {
		return errors.Wrap(err, op)
	}
	if err := sc.Format.Validate(); err != nil {
		return errors.Wrap(err, op)
	}
	if sc.SinkType == FileSink && sc.FileName == "" {
		return errors.New(errors.InvalidParameter, op, "missing sink file name")
	}
	if sc.Name == "" {
		return errors.New(errors.InvalidParameter, op, "missing sink name")
	}
	if len(sc.EventTypes) == 0 {
		return errors.New(errors.InvalidParameter, op, "missing event types")
	}
	for _, et := range sc.EventTypes {
		if err := et.validate(); err != nil {
			return errors.Wrap(err, op)
		}
	}
	return nil
}
