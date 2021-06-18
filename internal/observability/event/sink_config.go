package event

import (
	"fmt"
	"time"
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
		return fmt.Errorf("%s: %w", op, err)
	}
	if err := sc.Format.validate(); err != nil {
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
