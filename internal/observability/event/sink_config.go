package event

import (
	"fmt"
	"time"
)

// SinkConfig defines the configuration for a Eventer sink
type SinkConfig struct {
	Name           string        `hcl:"name"`             // Name defines a name for the sink.
	Description    string        `hcl:"description"`      // Description defines a description for the sink.
	EventTypes     []Type        `hcl:"event_types"`      // EventTypes defines a list of event types that will be sent to the sink. See the docs for EventTypes for a list of accepted values.
	EventSourceUrl string        `hcl:"event_source_url"` // EventSource defines an optional event source URL for the sink.  If not defined a default source will be composed of the https://hashicorp.com/boundary.io/ServerName/Path/FileName
	AllowFilters   []string      `hcl:"allow_filters"`    // AllowFilters define a set predicates for including an event in the sink.  If any filter matches, the event will be included. The filter should be in a format supported by hashicorp/go-bexpr.
	DenyFilters    []string      `hcl:"deny_filters"`     // DenyFilters define a set predicates for excluding an event in the sink.  If any filter matches, the event will be excluded. The filter should be in a format supported by hashicorp/go-bexpr.
	SinkType       SinkType      `hcl:"sink_type"`        // SinkType defines the type of sink (StderrSink or FileSink)
	Format         SinkFormat    `hcl:"format"`           // Format defines the format for the sink (JSONSinkFormat or TextSinkFormat)
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

// FilterType defines a type for filters (allow or deny)
type FilterType string

const (
	AllowFilter FilterType = "allow" // AllowFilter defines a filter type for "allow"
	DenyFilter  FilterType = "deny"  // DenyFilter defines a filter type for "deny"
)

// SinkFilter defines an event filter (allow or deny) for a sink
type SinkFilter struct {
	Type   FilterType `hcl:"type"`   // Type of filter (allow or deny)
	Filter string     `hcl:"filter"` // Filter in a format supported by hashicorp/go-bexpr.
}

// Validate a SinkFilter
func (s SinkFilter) Validate() error {
	const op = "event.(SinkFilter).Validate"
	switch s.Type {
	case AllowFilter, DenyFilter:
	default:
		return fmt.Errorf("%s: invalid filter type %s: %w", op, s.Type, ErrInvalidParameter)
	}
	_, err := newFilter(s.Filter)
	if err != nil {
		return fmt.Errorf("%s: invalid filter '%s': %w", op, s.Filter, err)
	}
	return nil
}
