package event

import (
	"time"

	"github.com/hashicorp/boundary/internal/errors"
)

const AuditVersion = "v0.1"

type AuditEventType string

const (
	ApiRequest AuditEventType = "APIRequest"
)

type audit struct {
	Id             string       `json:"id"`                     // std audit/boundary field
	Version        string       `json:"version"`                // std audit/boundary field
	Op             Op           `json:"op"`                     // std boundary field
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
		Op:          fromOperation,
		Version:     AuditVersion,
		Type:        string(ApiRequest),
		Timestamp:   dtm,
		RequestInfo: opts.withRequestInfo,
		Auth:        opts.withAuth,
		Request:     opts.withRequest,
		Response:    opts.withResponse,
	}
	if err := a.validate(); err != nil {
		return nil, errors.Wrap(err, op)
	}
	return a, nil
}

// EventType is required for all event types by the eventlogger broker
func (a *audit) EventType() string { return string(AuditType) }

func (a *audit) validate() error {
	const op = "event.(Audti).validate"
	if a.Id == "" {
		return errors.New(errors.InvalidParameter, op, "missing event id")
	}
	if a.Op == "" {
		return errors.New(errors.InvalidParameter, op, "missing operation which raised event")
	}
	return nil
}
