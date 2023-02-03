// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package event

import (
	"fmt"

	"github.com/hashicorp/eventlogger"
	"github.com/hashicorp/eventlogger/filters/gated"
	"github.com/hashicorp/go-secure-stdlib/strutil"
)

// observationVersion defines the version of observation events
const observationVersion = "v0.1"

type observation struct {
	Version     string         `json:"version"`
	Op          Op             `json:"op,omitempty"`
	RequestInfo *RequestInfo   `json:"request_info,omitempty"`
	ID          string         `json:"-"`
	Flush       bool           `json:"-"`
	Header      map[string]any `json:"header,omitempty"`
	Detail      map[string]any `json:"detail,omitempty"`
}

func newObservation(fromOperation Op, opt ...Option) (*observation, error) {
	const op = "event.newObservation"
	if fromOperation == "" {
		return nil, fmt.Errorf("%s: missing operation: %w", op, ErrInvalidParameter)
	}
	opts := getOpts(opt...)
	if opts.withId == "" {
		var err error
		opts.withId, err = NewId(string(ObservationType))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
	}
	for k := range opts.withHeader {
		if strutil.StrListContains([]string{OpField, VersionField, RequestInfoField}, k) {
			return nil, fmt.Errorf("%s: %s is a reserved field name: %w", op, k, ErrInvalidParameter)
		}
	}
	i := &observation{
		ID:          opts.withId,
		Header:      opts.withHeader,
		Detail:      opts.withDetails,
		Flush:       opts.withFlush,
		Op:          fromOperation,
		RequestInfo: opts.withRequestInfo,
		Version:     observationVersion,
	}
	if err := i.validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return i, nil
}

// EventType is required for all event types by the eventlogger broker
func (o *observation) EventType() string { return string(ObservationType) }

func (o *observation) validate() error {
	const op = "event.(Observation).validate"
	if o.ID == "" {
		return fmt.Errorf("%s: missing id: %w", op, ErrInvalidParameter)
	}
	if o.Op == "" {
		return fmt.Errorf("%s: missing operation: %w", op, ErrInvalidParameter)
	}
	return nil
}

// ComposedFrom will build a single event payload which will be
// Flushed/Processed from a collection of gated observation events.  The payload
// returned is  not a Gateable payload intentionally.  Note: the receiver is
// always nil when this function is called.
func (o *observation) ComposeFrom(events []*eventlogger.Event) (eventlogger.EventType, any, error) {
	const op = "event.(observation).ComposedFrom"
	if len(events) == 0 {
		return "", nil, fmt.Errorf("%s: missing events: %w", op, eventlogger.ErrInvalidParameter)
	}

	payload := map[string]any{}
	for i, v := range events {
		g, ok := v.Payload.(*observation)
		if !ok {
			return "", nil, fmt.Errorf("%s: event %d is not an observation: %w", op, i, eventlogger.ErrInvalidParameter)
		}
		if g.Header != nil {
			for hdrK, hdrV := range g.Header {
				payload[hdrK] = hdrV
			}
		}
		if g.Detail != nil {
			if _, ok := payload[DetailsField]; !ok {
				payload[DetailsField] = []gated.EventPayloadDetails{}
			}
			payload[DetailsField] = append(payload[DetailsField].([]gated.EventPayloadDetails), gated.EventPayloadDetails{
				Type:      string(v.Type),
				CreatedAt: v.CreatedAt.String(),
				Payload:   g.Detail,
			})
		}
	}
	return events[0].Type, payload, nil
}

var _ gated.Gateable = &observation{}

// GetID returns the unique id used for gating
func (o *observation) GetID() string {
	return o.ID
}

// FlushEvent tells the Filter to flush/process the events associated with
// the Gateable ID
func (o *observation) FlushEvent() bool {
	return o.Flush
}
