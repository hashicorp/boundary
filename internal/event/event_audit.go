// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package event

import (
	"fmt"
	"time"

	"github.com/hashicorp/eventlogger"
)

// auditVersion defines the version of audit events
const auditVersion = "v0.1"

// auditEventType defines the type of audit event
type auditEventType string

const (
	ApiRequest auditEventType = "APIRequest" // ApiRequest defines an API request audit event type
)

// audit defines the data of audit events
type audit struct {
	Id            string       `json:"id"`                     // std audit/boundary field
	Version       string       `json:"version"`                // std audit/boundary field
	Type          string       `json:"type"`                   // std audit field
	Timestamp     time.Time    `json:"timestamp"`              // std audit field
	RequestInfo   *RequestInfo `json:"request_info,omitempty"` // boundary field
	Auth          *Auth        `json:"auth,omitempty"`         // std audit field
	Request       *Request     `json:"request,omitempty"`      // std audit field
	Response      *Response    `json:"response,omitempty"`     // std audit field
	Flush         bool         `json:"-"`
	CorrelationId string       `json:"correlation_id,omitempty"`
}

func newAudit(fromOperation Op, opt ...Option) (*audit, error) {
	const op = "event.newAudit"
	if fromOperation == "" {
		return nil, fmt.Errorf("%s: missing from operation: %w", op, ErrInvalidParameter)
	}
	opts := getOpts(opt...)
	if opts.withId == "" {
		var err error
		opts.withId, err = NewId(string(AuditType))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
	}
	var dtm time.Time
	switch opts.withNow.IsZero() {
	case false:
		dtm = opts.withNow
	default:
		dtm = time.Now()
	}

	a := &audit{
		Id:            opts.withId,
		Version:       auditVersion,
		Type:          string(ApiRequest),
		Timestamp:     dtm,
		RequestInfo:   opts.withRequestInfo,
		Auth:          opts.withAuth,
		Request:       opts.withRequest,
		Response:      opts.withResponse,
		Flush:         opts.withFlush,
		CorrelationId: opts.withCorrelationId,
	}
	if err := a.validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return a, nil
}

// EventType is required for all event types by the eventlogger broker
func (a *audit) EventType() string { return string(AuditType) }

func (a *audit) validate() error {
	const op = "event.(audit).validate"
	if a.Id == "" {
		return fmt.Errorf("%s: missing id: %w", op, ErrInvalidParameter)
	}
	return nil
}

// GetID is part of the eventlogger.Gateable interface and returns the audit
// event's id.
func (a *audit) GetID() string {
	return a.Id
}

// FlushEvent is part of the eventlogger.Gateable interface and returns the
// value of the audit event's flush field
func (a *audit) FlushEvent() bool {
	return a.Flush
}

// ComposedFrom is part of the eventlogger.Gatable interface.  It's important to
// remember that the receiver will always be nil when this is called by the eventlogger.GatedFilter
func (a *audit) ComposeFrom(events []*eventlogger.Event) (eventlogger.EventType, any, error) {
	const op = "event.(audit).ComposedFrom"
	if len(events) == 0 {
		return "", nil, fmt.Errorf("%s: missing events: %w", op, ErrInvalidParameter)
	}
	var validId string
	payload := audit{}
	for i, v := range events {
		gated, ok := v.Payload.(*audit)
		if !ok {
			return "", nil, fmt.Errorf("%s: event %d is not an audit payload: %w", op, i, ErrInvalidParameter)
		}
		if gated.Id == "" {
			// can't really happen since it has to have an id to be gated, but
			// I'll add this check in the name of completeness
			return "", nil, fmt.Errorf("%s: event %d: id is required: %w", op, i, ErrInvalidParameter)
		}
		if validId == "" {
			validId = gated.Id
		}
		if gated.Id != validId {
			return "", nil, fmt.Errorf("%s: event %d has an invalid id: %s != %s: %w", op, i, gated.Id, validId, ErrInvalidParameter)
		}
		if gated.Version != auditVersion {
			return "", nil, fmt.Errorf("%s: event %d has an invalid version: %s != %s: %w", op, i, gated.Version, auditVersion, ErrInvalidParameter)
		}
		if gated.Type != string(ApiRequest) {
			return "", nil, fmt.Errorf("%s: event %d has an invalid type: %s != %s: %w", op, i, gated.Type, string(AuditType), ErrInvalidParameter)
		}
		if gated.RequestInfo != nil {
			payload.RequestInfo = gated.RequestInfo
		}
		if gated.Auth != nil {
			payload.Auth = gated.Auth
		}
		if gated.Request != nil {
			if payload.Request == nil {
				payload.Request = &Request{}
			}
			if gated.Request.Endpoint != "" {
				payload.Request.Endpoint = gated.Request.Endpoint
			}
			if gated.Request.Operation != "" {
				payload.Request.Operation = gated.Request.Operation
			}
			if gated.Request.Details != nil {
				payload.Request.Details = gated.Request.Details
			}
			if gated.Request.DetailsUpstreamMessage != nil {
				payload.Request.DetailsUpstreamMessage = gated.Request.DetailsUpstreamMessage
			}
		}
		if gated.Response != nil {
			if payload.Response == nil {
				payload.Response = &Response{}
			}
			if gated.Response.StatusCode != 0 {
				payload.Response.StatusCode = gated.Response.StatusCode
			}
			if gated.Response.Details != nil {
				payload.Response.Details = gated.Response.Details
			}
			if gated.Response.DetailsUpstreamMessage != nil {
				payload.Response.DetailsUpstreamMessage = gated.Response.DetailsUpstreamMessage
			}
		}
		if !gated.Timestamp.IsZero() {
			payload.Timestamp = gated.Timestamp
		}
		if gated.CorrelationId != "" {
			payload.CorrelationId = gated.CorrelationId
		}
	}
	payload.Id = validId
	payload.Version = auditVersion
	payload.Type = string(ApiRequest)
	return eventlogger.EventType(a.EventType()), payload, nil
}
