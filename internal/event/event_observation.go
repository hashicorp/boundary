// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package event

import (
	"encoding/json"
	"fmt"
	"reflect"

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
	Request     *Request       `json:"request,omitempty"`
	Response    *Response      `json:"response,omitempty"`
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
		Request:     opts.withRequest,
		Response:    opts.withResponse,
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
		if g.Request != nil {
			msgReq := &Request{}
			if v, ok := payload["request"]; ok {
				msgReq, ok = v.(*Request)
				if !ok {
					return "", nil, fmt.Errorf("%s: request %d is not an observation request: %w", op, i, eventlogger.ErrInvalidParameter)
				}
			}
			if g.Request.Details != nil {
				res := recurseStructureWithTagFilter(
					g.Request.Details,
					map[string]string{
						"eventstream": "observation",
					},
					false,
				)
				data, _ := json.Marshal(res)
				fmt.Printf("RESULT request = %s", string(data))
				msgReq.Details = g.Request.Details
			}
			if g.Request.Operation != "" {
				msgReq.Operation = g.Request.Operation
			}
			if g.Request.Endpoint != "" {
				msgReq.Endpoint = g.Request.Endpoint
			}
			if g.Request.DetailsUpstreamMessage != nil {
				msgReq.DetailsUpstreamMessage = g.Request.DetailsUpstreamMessage
			}
			payload["request"] = msgReq
		}
		if g.Response != nil {
			msgRes := &Response{}
			if v, ok := payload["response"]; ok {
				msgRes, ok = v.(*Response)
				if !ok {
					return "", nil, fmt.Errorf("%s: response %d is not an observation response: %w", op, i, eventlogger.ErrInvalidParameter)
				}
			}
			if g.Response.StatusCode != 0 {
				msgRes.StatusCode = g.Response.StatusCode
			}
			if g.Response.Details != nil {
				res := recurseStructureWithTagFilter(
					g.Response.Details,
					map[string]string{
						"eventstream": "observation",
					},
					false,
				)
				data, _ := json.Marshal(res)
				fmt.Printf("RESULT response = %s \n", string(data))

				msgRes.Details = g.Response.Details
			}
			if g.Response.DetailsUpstreamMessage != nil {
				msgRes.DetailsUpstreamMessage = g.Response.DetailsUpstreamMessage
			}
			payload["response"] = msgRes
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

func recurseStructureWithTagFilter(value any, allowedStructTags map[string]string, allowLevel bool) any {
	if allowedStructTags == nil {
		allowedStructTags = map[string]string{}
	}

	kind := reflect.ValueOf(value).Kind()

	switch kind {
	case reflect.Interface, reflect.Ptr:
		value = reflect.ValueOf(value).Elem().Interface()
		return recurseStructureWithTagFilter(value, allowedStructTags, allowLevel)
	case reflect.Map:
		out := map[string]any{}
		m := reflect.ValueOf(value)
		for _, k := range m.MapKeys() {
			mVal := m.MapIndex(k).Interface()
			if vv := recurseStructureWithTagFilter(mVal, allowedStructTags, allowLevel); vv != nil {
				if strKey, ok := k.Interface().(string); ok {
					out[strKey] = vv
				} else {
					out[fmt.Sprintf("%v", k)] = vv
				}
			}
		}
		if allowLevel {
			return out
		}
		return nil
	case reflect.Array, reflect.Slice:
		out := []any{}
		s := reflect.ValueOf(value)
		for i := 0; i < s.Len(); i++ {
			sVal := s.Index(i).Interface()
			if vv := recurseStructureWithTagFilter(sVal, allowedStructTags, allowLevel); vv != nil {
				out = append(out, vv)
			}
		}
		if allowLevel {
			return out
		}
		return nil
	case reflect.Struct:
		// traverse the struct recursively, and apply any tag filters
		fields := reflect.TypeOf(value)
		values := reflect.ValueOf(value)
		num := fields.NumField()
		out := map[string]any{}
		for i := 0; i < num; i++ {
			field := fields.Field(i)
			name := field.Name
			allowLevel := false
			if len(allowedStructTags) == 0 {
				allowLevel = true
			} else {
				for tag, tagValue := range allowedStructTags {
					if field.Tag.Get(tag) == tagValue {
						// log.Printf("%s is allowed by Tags (%s:\"%s\")", name, tag, tagValue)
						allowLevel = true
						break
					}
				}
			}
			if !field.IsExported() {
				continue
			}
			if values.Field(i).IsZero() {
				if allowLevel {
					out[name] = ""
				}
				continue
			}
			if !values.Field(i).IsValid() {
				continue
			}
			value := values.Field(i).Interface()
			if vv := recurseStructureWithTagFilter(value, allowedStructTags, allowLevel); vv != nil {
				out[name] = vv
			}
		}
		return out
	default:
		// any other non structured type, we will just barf out as is
		if allowLevel {
			return value
		}
		return nil
	}
}
