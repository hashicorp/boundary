package event

import (
	"fmt"
	"time"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/eventlogger"
)

// auditVersion defines the version of audit events
const auditVersion = "v0.1"

// auditEventType defines the type of audit event
type auditEventType string

const (
	apiRequest auditEventType = "APIRequest" // ApiRequest defines an API request audit event type
)

// audit defines the data of audit events
type audit struct {
	Id             string       `json:"id"`                     // std audit/boundary field
	Version        string       `json:"version"`                // std audit/boundary field
	Type           string       `json:"type"`                   // std audit field
	Timestamp      time.Time    `json:"timestamp"`              // std audit field
	RequestInfo    *RequestInfo `json:"request_info,omitempty"` // boundary field
	Auth           *Auth        `json:"auth,omitempty"`         // std audit field
	Request        *Request     `json:"request,omitempty"`      // std audit field
	Response       *Response    `json:"response,omitempty"`     // std audit field
	SerializedHMAC string       `json:"serialized_hmac"`        // boundary field
	Flush          bool         `json:"-"`
}

func newAudit(fromOperation Op, opt ...Option) (*audit, error) {
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

	a := &audit{
		Id:          opts.withId,
		Version:     auditVersion,
		Type:        string(apiRequest),
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
func (a *audit) EventType() string { return string(AuditType) }

func (a *audit) validate() error {
	const op = "event.(audit).validate"
	if a.Id == "" {
		return errors.New(errors.InvalidParameter, op, "missing id")
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
func (a *audit) ComposeFrom(events []*eventlogger.Event) (eventlogger.EventType, interface{}, error) {
	const op = "event.(audit).ComposedFrom"
	if len(events) == 0 {
		return "", nil, errors.New(errors.InvalidParameter, op, "missing events")
	}
	var validId string
	payload := audit{}
	for i, v := range events {
		gated, ok := v.Payload.(*audit)
		if !ok {
			return "", nil, errors.New(errors.InvalidParameter, op, fmt.Sprintf("event %d is not an audit payload", i))
		}
		if gated.Id == "" {
			// can't really happen since it has to have an id to be gated, but
			// I'll add this check in the name of completeness
			return "", nil, errors.New(errors.InvalidParameter, op, fmt.Sprintf("event %d: id is required", i))
		}
		if validId == "" {
			validId = gated.Id
		}
		if gated.Id != validId {
			return "", nil, errors.New(errors.InvalidParameter, op, fmt.Sprintf("event %d has an invalid id: %s != %s", i, gated.Id, validId))
		}
		if gated.Version != auditVersion {
			return "", nil, errors.New(errors.InvalidParameter, op, fmt.Sprintf("event %d has an invalid version: %s != %s", i, gated.Version, auditVersion))
		}
		if gated.Type != string(apiRequest) {
			return "", nil, errors.New(errors.InvalidParameter, op, fmt.Sprintf("event %d has an invalid type: %s != %s", i, gated.Type, string(AuditType)))
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

	}
	payload.Id = validId
	payload.Version = auditVersion
	payload.Type = string(apiRequest)
	return eventlogger.EventType(a.EventType()), payload, nil
}
