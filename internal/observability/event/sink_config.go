package event

import (
	"time"

	"github.com/hashicorp/boundary/internal/errors"
)

// SinkConfig defines the configuration for a Eventer sink
type SinkConfig struct {
	Name           string        `hcl:"name"`             // Name defines a name for the sink.
	EventTypes     []Type        `hcl:"event_types"`      // EventTypes defines a list of event types that will be sent to the sink. See the docs for EventTypes for a list of accepted values.
	SinkType       SinkType      `hcl:"sink_type"`        // SinkType defines the type of sink (StderrSink or FileSink)
	Format         SinkFormat    `hcl:"format"`           // Format defines the format for the sink (JSONSinkFormat)
	Path           string        `hcl:"path"`             // Path defines the file path for the sink
	FileName       string        `hcl:"file_name"`        // FileName defines the file name for the sink
	RotateBytes    int           `hcl:"rotate_bytes"`     // RotateByes defines the number of bytes that should trigger rotation of a FileSink
	RotateDuration time.Duration `hcl:"rotate_duration"`  // RotateDuration defines how often a FileSink should be rotated
	RotateMaxFiles int           `hcl:"rotate_max_files"` // RotateMaxFiles defines how may historical rotated files should be kept for a FileSink
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
