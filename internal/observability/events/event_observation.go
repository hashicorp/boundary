package event

import (
	"fmt"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/eventlogger"
	"github.com/hashicorp/vault/sdk/helper/strutil"
)

const ObservationVersion = "v0.1"

type observation struct {
	*eventlogger.SimpleGatedPayload
	Version     string       `json:"version"`
	Op          Op           `json:"op,omitempty"`
	RequestInfo *RequestInfo `json:"request_info,omitempty"`
}

func newObservation(fromOperation Op, opt ...Option) (*observation, error) {
	const op = "event.newObservation"
	if fromOperation == "" {
		return nil, errors.New(errors.InvalidParameter, op, "missing operation")
	}
	opts := getOpts(opt...)
	if opts.withId == "" {
		var err error
		opts.withId, err = newId(string(ObservationType))
		if err != nil {
			return nil, errors.Wrap(err, op)
		}
	}
	for k := range opts.withHeader {
		if strutil.StrListContains([]string{OpField, VersionField, RequestInfoField}, k) {
			return nil, errors.New(errors.InvalidParameter, op, fmt.Sprintf("%s is a reserved field name", k))
		}
	}
	i := &observation{
		SimpleGatedPayload: &eventlogger.SimpleGatedPayload{
			ID:     opts.withId,
			Header: opts.withHeader,
			Detail: opts.withDetails,
			Flush:  opts.withFlush,
		},
		Op:          fromOperation,
		RequestInfo: opts.withRequestInfo,
		Version:     ObservationVersion,
	}
	if err := i.validate(); err != nil {
		return nil, errors.Wrap(err, op)
	}
	return i, nil
}

// EventType is required for all event types by the eventlogger broker
func (i *observation) EventType() string { return string(ObservationType) }

func (i *observation) validate() error {
	const op = "event.(Observation).validate"
	if i.ID == "" {
		return errors.New(errors.InvalidParameter, op, "missing id")
	}
	if i.Op == "" {
		return errors.New(errors.InvalidParameter, op, "missing operation")
	}
	return nil
}
