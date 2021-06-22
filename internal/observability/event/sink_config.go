package event

import (
	"fmt"
	"time"
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
		return fmt.Errorf("%s: %w", op, err)
	}
	if err := sc.Format.Validate(); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	if sc.SinkType == FileSink && sc.FileName == "" {
		return fmt.Errorf("%s: missing sink file name: %w", op, ErrInvalidParameter)
	}
	if sc.Name == "" {
		return fmt.Errorf("%s: missing sink name: %w", op, ErrInvalidParameter)
	}
	if len(sc.EventTypes) == 0 {
		return fmt.Errorf("%s: missing event types: %w", op, ErrInvalidParameter)
	}
	for _, et := range sc.EventTypes {
		if err := et.validate(); err != nil {
			return fmt.Errorf("%s: %w", op, err)
		}
	}
	return nil
}
