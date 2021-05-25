package event

import (
	"fmt"
	"time"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/eventlogger"
)

const AuditVersion = "v0.1"

type AuditEventType string

const (
	ApiRequest AuditEventType = "APIRequest"
)

type Audit struct {
	Id             string       `json:"id"`                     // std audit/boundary field
	Version        string       `json:"version"`                // std audit/boundary field
	Type           string       `json:"type"`                   // std audit field
	Timestamp      time.Time    `json:"timestamp"`              // std audit field
	RequestInfo    *RequestInfo `json:"request_info,omitempty"` // boundary field
	Auth           *Auth        `json:"auth,omitempty"`         // std audit field
	Request        *Request     `json:"request,omitempty"`      // std audit field
	Response       *Response    `json:"response,omitempty"`     // std audit field
	Serialized     []byte       `json:"serialized"`             // boundary field
	SerializedHMAC string       `json:"serialized_hmac"`        // boundary field
	Flush          bool         `json:"-"`
}

func newAudit(fromOperation Op, opt ...Option) (*Audit, error) {
	const op = "event.newAudit"
	if fromOperation == "" {
		return nil, errors.New(errors.InvalidParameter, op, "missing from operation")
	}
	opts := getOpts(opt...)
	if opts.withId == "" {
		var err error
		opts.withId, err = newId(string(AuditType))
		if err != nil {
			return nil, errors.Wrap(err, op)
		}
	}
	var dtm time.Time
	switch opts.withNow.IsZero() {
	case false:
		dtm = opts.withNow
	default:
		dtm = time.Now()
	}

	a := &Audit{
		Id:          opts.withId,
		Version:     AuditVersion,
		Type:        string(ApiRequest),
		Timestamp:   dtm,
		RequestInfo: opts.withRequestInfo,
		Auth:        opts.withAuth,
		Request:     opts.withRequest,
		Response:    opts.withResponse,
		Flush:       opts.withFlush,
	}
	if err := a.validate(); err != nil {
		return nil, errors.Wrap(err, op)
	}
	return a, nil
}

// EventType is required for all event types by the eventlogger broker
func (a *Audit) EventType() string { return string(AuditType) }

func (a *Audit) validate() error {
	const op = "event.(audit).validate"
	if a.Id == "" {
		return errors.New(errors.InvalidParameter, op, "missing event id")
	}
	return nil
}

// GetID is part of the eventlogger.Gateable interface and returns the audit
// event's id.
func (a *Audit) GetID() string {
	return a.Id
}

// FlushEvent is part of the eventlogger.Gateable interface and returns the
// value of the audit event's flush field
func (a *Audit) FlushEvent() bool {
	return a.Flush
}

func (a *Audit) ComposeFrom(events []*eventlogger.Event) (eventlogger.EventType, interface{}, error) {
	const op = "event.(audit).ComposedFrom"
	if len(events) == 0 {
		return "", nil, errors.New(errors.InvalidParameter, op, "missing events")

	}
	payload := Audit{}
	for i, v := range events {
		gated, ok := v.Payload.(*Audit)
		if !ok {
			return "", nil, errors.New(errors.InvalidParameter, op, fmt.Sprintf("event %d is not a simple gated payload", i))
		}
		if gated.RequestInfo != nil {
			payload.RequestInfo = gated.RequestInfo
		}
		if gated.Auth != nil {
			payload.Auth = gated.Auth
		}
		if gated.Request != nil {
			payload.Request = gated.Request
		}
		if gated.Response != nil {
			payload.Response = gated.Response
		}
		if !gated.Timestamp.IsZero() {
			payload.Timestamp = gated.Timestamp
		}
		payload.Id = gated.Id
		payload.Version = gated.Version
		payload.Type = gated.Type
	}
	return eventlogger.EventType(a.EventType()), payload, nil
}
