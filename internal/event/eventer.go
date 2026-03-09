// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package event

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/eventlogger"
	"github.com/hashicorp/eventlogger/filters/encrypt"
	"github.com/hashicorp/eventlogger/filters/gated"
	"github.com/hashicorp/eventlogger/formatter_filters/cloudevents"
	"github.com/hashicorp/eventlogger/sinks/writer"
	"github.com/hashicorp/go-hclog"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"go.uber.org/atomic"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

const (
	OpField          = "op"           // OpField in an event.
	RequestInfoField = "request_info" // RequestInfoField in an event.
	VersionField     = "version"      // VersionField in an event
	DetailsField     = "details"      // Details field in an event.
	HeaderField      = "header"       // HeaderField in an event.
	IdField          = "id"           // IdField in an event.
	CreatedAtField   = "created_at"   // CreatedAtField in an event.
	TypeField        = "type"         // TypeField in an event.
	RequestField     = "request"      // Request field in an event.
	ResponseField    = "response"     // Response field in an event.

	auditPipeline       = "audit-pipeline"       // auditPipeline is a pipeline for audit events
	observationPipeline = "observation-pipeline" // observationPipeline is a pipeline for observation events
	errPipeline         = "err-pipeline"         // errPipeline is a pipeline for error events
	sysPipeline         = "sys-pipeline"         // sysPipeline is a pipeline for system events
)

// flushable defines an interface that all eventlogger Nodes must implement if
// they are "flushable"
type flushable interface {
	FlushAll(ctx context.Context) error
}

// broker defines an interface for an eventlogger Broker... which will allow us
// to substitute our testing broker when needed to write tests for things
// like event send retrying.
type broker interface {
	Send(ctx context.Context, t eventlogger.EventType, payload any) (eventlogger.Status, error)
	Reopen(ctx context.Context) error
	StopTimeAt(now time.Time)
	RegisterNode(id eventlogger.NodeID, node eventlogger.Node, opt ...eventlogger.Option) error
	RemoveNode(ctx context.Context, id eventlogger.NodeID) error
	SetSuccessThreshold(t eventlogger.EventType, successThreshold int) error
	RegisterPipeline(def eventlogger.Pipeline, opt ...eventlogger.Option) error
	RemovePipelineAndNodes(ctx context.Context, t eventlogger.EventType, id eventlogger.PipelineID) (bool, error)
}

// queuedEvent stores an event and the context that was associated with it when
// gating
type queuedEvent struct {
	ctx   context.Context
	event any
}

// Eventer provides a method to send events to pipelines of sinks
type Eventer struct {
	broker               broker
	serverName           string
	flushableNodes       []flushable
	conf                 EventerConfig
	logger               hclog.Logger
	auditPipelines       []pipeline
	observationPipelines []pipeline
	errPipelines         []pipeline
	auditWrapperNodes    []any

	// Gating is used to delay output of events until after we have a chance to
	// render startup info, similar to what was done for hclog before eventing
	// supplanted it. It affects only error and system events.
	gated          atomic.Bool
	gatedQueue     []*queuedEvent
	gatedQueueLock *sync.Mutex
}

type node struct {
	node eventlogger.Node
	id   eventlogger.NodeID
}

type pipeline struct {
	eventType       Type
	fmtId           eventlogger.NodeID
	sinkId          eventlogger.NodeID
	gateId          eventlogger.NodeID
	encryptFilterId eventlogger.NodeID
	sinkConfig      *SinkConfig
}

var (
	sysEventer        *Eventer     // sysEventer is the system-wide Eventer
	sysEventerLock    sync.RWMutex // sysEventerLock allows the sysEventer to safely be written concurrently.
	sysFallbackLogger struct {
		mu     sync.RWMutex
		logger hclog.Logger
	}
)

func defaultLogger() hclog.Logger {
	opts := new(hclog.LoggerOptions)
	*opts = *hclog.DefaultOptions
	opts.JSONFormat = true
	return hclog.New(opts)
}

// fallbackLogger returns the current fallback logger for eventing.  If there's
// no current fallback logger, then a default logger is returned.
func fallbackLogger() hclog.Logger {
	sysFallbackLogger.mu.RLock()
	defer sysFallbackLogger.mu.RUnlock()
	if sysFallbackLogger.logger == nil {
		return defaultLogger()
	}
	return sysFallbackLogger.logger
}

// InitFallbackLogger will initialize the fallback logger for eventing
func InitFallbackLogger(l hclog.Logger) error {
	const op = "event.InitFallbackLogger"
	if isNil(l) {
		return fmt.Errorf("%s: missing logger: %w", op, ErrInvalidParameter)
	}

	sysFallbackLogger.mu.Lock()
	defer sysFallbackLogger.mu.Unlock()
	sysFallbackLogger.logger = l

	return nil
}

// InitSysEventer provides a mechanism to initialize a "system wide" eventer
// singleton for Boundary.  Support the options of: WithEventer(...) and
// WithEventerConfig(...)
//
// IMPORTANT: Eventers cannot share file sinks, which likely means that each
// process should only have one Eventer.  In practice this means the process
// Server (Controller or Worker) and the SysEventer both need a pointer to a
// single Eventer.
func InitSysEventer(log hclog.Logger, serializationLock *sync.Mutex, serverName string, opt ...Option) error {
	const op = "event.InitSysEventer"
	if log == nil {
		return fmt.Errorf("%s: missing hclog: %w", op, ErrInvalidParameter)
	}
	if serializationLock == nil {
		return fmt.Errorf("%s: missing serialization lock: %w", op, ErrInvalidParameter)
	}
	if serverName == "" {
		return fmt.Errorf("%s: missing server name: %w", op, ErrInvalidParameter)
	}

	// the order of operations is important here.  we want to determine if
	// there's an error before setting the singleton sysEventer
	var e *Eventer
	opts := getOpts(opt...)
	switch {
	case opts.withEventer == nil && opts.withEventerConfig == nil:
		return fmt.Errorf("%s: missing both eventer and eventer config: %w", op, ErrInvalidParameter)

	case opts.withEventer != nil && opts.withEventerConfig != nil:
		return fmt.Errorf("%s: both eventer and eventer config provided: %w", op, ErrInvalidParameter)

	case opts.withEventerConfig != nil:
		var err error
		if e, err = NewEventer(log, serializationLock, serverName, *opts.withEventerConfig); err != nil {
			return fmt.Errorf("%s: %w", op, err)
		}

	case opts.withEventer != nil:
		e = opts.withEventer
	}

	sysEventerLock.Lock()
	defer sysEventerLock.Unlock()
	sysEventer = e
	return nil
}

// SysEventer returns the "system wide" eventer for Boundary and can/will return
// a nil Eventer
func SysEventer() *Eventer {
	sysEventerLock.RLock()
	defer sysEventerLock.RUnlock()
	return sysEventer
}

// NewAuditEncryptFilter returns a new encrypt filter which is initialized for
// audit events.
func NewAuditEncryptFilter(opt ...Option) (*encrypt.Filter, error) {
	opts := getOpts(opt...)

	return &encrypt.Filter{
		Wrapper: opts.withAuditWrapper,
		IgnoreTypes: []reflect.Type{
			reflect.TypeOf(&fieldmaskpb.FieldMask{}),
		},
	}, nil
}

// NewEventer creates a new Eventer using the config.  Supports options:
// WithNow, WithSerializationLock, WithBroker, WithAuditWrapper,
// WithNoDefaultSink
func NewEventer(log hclog.Logger, serializationLock *sync.Mutex, serverName string, c EventerConfig, opt ...Option) (*Eventer, error) {
	const op = "event.NewEventer"
	if log == nil {
		return nil, fmt.Errorf("%s: missing logger: %w", op, ErrInvalidParameter)
	}
	if serializationLock == nil {
		return nil, fmt.Errorf("%s: missing serialization lock: %w", op, ErrInvalidParameter)
	}
	if serverName == "" {
		return nil, fmt.Errorf("%s: missing server name: %w", op, ErrInvalidParameter)
	}

	opts := getOpts(opt...)

	// if there are no sinks in config, then we'll default to just one stderr
	// sink.
	if len(c.Sinks) == 0 && !opts.withNoDefaultSink {
		c.Sinks = append(c.Sinks, DefaultSink())
	}

	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	var auditPipelines, observationPipelines, errPipelines, sysPipelines []pipeline

	var b broker
	switch {
	case opts.withBroker != nil:
		b = opts.withBroker
	default:
		b, _ = eventlogger.NewBroker()
	}

	e := &Eventer{
		gatedQueueLock:    new(sync.Mutex),
		logger:            log,
		conf:              c,
		broker:            b,
		auditWrapperNodes: []any{},
		serverName:        serverName,
	}

	if !opts.withNow.IsZero() {
		e.broker.StopTimeAt(opts.withNow)
	}

	if opts.withGating {
		e.gated.Store(true)
	}

	// serializedStderr will be shared among all StderrSinks so their output is not
	// interwoven
	serializedStderr := serializedWriter{
		w: os.Stderr,
		l: serializationLock,
	}

	// we need to keep track of all the Sink filenames to ensure they aren't
	// reused.
	allSinkFilenames := map[string]bool{}

	for _, s := range c.Sinks {
		fmtId, fmtNode, err := newFmtFilterNode(serverName, *s, opt...)
		e.auditWrapperNodes = append(e.auditWrapperNodes, fmtNode)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		err = e.broker.RegisterNode(eventlogger.NodeID(fmtId), fmtNode)
		if err != nil {
			return nil, fmt.Errorf("%s: unable to register fmt/filter node: %w", op, err)
		}

		var sinkId eventlogger.NodeID
		var sinkNode eventlogger.Node
		switch s.Type {
		case StderrSink:
			sinkNode = &writer.Sink{
				Format: string(s.Format),
				Writer: &serializedStderr,
			}
			id, err := NewId("stderr")
			if err != nil {
				return nil, fmt.Errorf("%s: %w", op, err)
			}
			sinkId = eventlogger.NodeID(id)
		case FileSink:
			fsc := s.FileConfig
			if _, found := allSinkFilenames[fsc.Path+fsc.FileName]; found {
				return nil, fmt.Errorf("%s: duplicate file sink: %s %s: %w", op, fsc.Path, fsc.FileName, ErrInvalidParameter)
			}
			allSinkFilenames[fsc.Path+fsc.FileName] = true
			sinkNode = &eventlogger.FileSink{
				Format:      string(s.Format),
				Path:        fsc.Path,
				FileName:    fsc.FileName,
				MaxBytes:    fsc.RotateBytes,
				MaxDuration: fsc.RotateDuration,
				MaxFiles:    fsc.RotateMaxFiles,
			}
			id, err := NewId(fmt.Sprintf("file_%s_%s_", fsc.Path, fsc.FileName))
			if err != nil {
				return nil, fmt.Errorf("%s: %w", op, err)
			}
			sinkId = eventlogger.NodeID(id)
		case WriterSink:
			wsc := s.WriterConfig
			sinkNode = &writer.Sink{
				Format: string(s.Format),
				Writer: wsc.Writer,
			}
			id, err := NewId("writer")
			if err != nil {
				return nil, fmt.Errorf("%s: %w", op, err)
			}
			sinkId = eventlogger.NodeID(id)
		default:
			return nil, fmt.Errorf("%s: unknown sink type %s", op, s.Type)
		}
		err = e.broker.RegisterNode(sinkId, sinkNode)
		if err != nil {
			return nil, fmt.Errorf("%s: failed to register sink node %s: %w", op, sinkId, err)
		}
		var addToAudit, addToObservation, addToErr, addToSys bool
		for _, t := range s.EventTypes {
			switch t {
			case EveryType:
				addToAudit = true
				addToObservation = true
				addToErr = true
				addToSys = true
			case ErrorType:
				addToErr = true
			case AuditType:
				addToAudit = true
			case ObservationType:
				addToObservation = true
			case SystemType:
				addToSys = true
			}
		}
		if addToAudit {
			var fop AuditFilterOperations
			if s.AuditConfig != nil {
				fop = s.AuditConfig.FilterOverrides
			}
			s.AuditConfig, err = NewAuditConfig(WithAuditWrapper(opts.withAuditWrapper), WithFilterOperations(fop))
			if err != nil {
				return nil, fmt.Errorf("%s: %w", op, err)
			}
			encryptFilter, err := NewAuditEncryptFilter(opt...)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", op, err)
			}
			e.auditWrapperNodes = append(e.auditWrapperNodes, encryptFilter)
			if len(s.AuditConfig.FilterOverrides) > 0 {
				overrides := encrypt.DefaultFilterOperations()
				for k, v := range s.AuditConfig.FilterOverrides {
					overrides[encrypt.DataClassification(k)] = encrypt.FilterOperation(v)
				}
				encryptFilter.FilterOperationOverrides = overrides
			}
			id, err := NewId("encrypt-audit")
			if err != nil {
				return nil, fmt.Errorf("%s: %w", op, err)
			}
			encryptFilterId := eventlogger.NodeID(id)
			if err := b.RegisterNode(encryptFilterId, encryptFilter); err != nil {
				return nil, fmt.Errorf("%s: %w", op, err)
			}
			auditPipelines = append(auditPipelines, pipeline{
				eventType:       AuditType,
				fmtId:           fmtId,
				sinkId:          sinkId,
				encryptFilterId: encryptFilterId,
				sinkConfig:      s,
			})
		}
		if addToObservation {
			observationPipelines = append(observationPipelines, pipeline{
				eventType:  ObservationType,
				fmtId:      fmtId,
				sinkId:     sinkId,
				sinkConfig: s,
			})
		}
		if addToErr {
			errPipelines = append(errPipelines, pipeline{
				eventType:  ErrorType,
				fmtId:      fmtId,
				sinkId:     sinkId,
				sinkConfig: s,
			})
		}
		if addToSys {
			sysPipelines = append(sysPipelines, pipeline{
				eventType: SystemType,
				fmtId:     fmtId,
				sinkId:    sinkId,
			})
		}
	}
	if c.AuditEnabled && len(auditPipelines) == 0 {
		return nil, fmt.Errorf("%s: audit events enabled but no sink defined for it: %w", op, ErrInvalidParameter)
	}
	if c.ObservationsEnabled && len(observationPipelines) == 0 {
		return nil, fmt.Errorf("%s: observation events enabled but no sink defined for it: %w", op, ErrInvalidParameter)
	}
	if c.SysEventsEnabled && len(sysPipelines) == 0 {
		return nil, fmt.Errorf("%s: system events enabled but no sink defined for it: %w", op, ErrInvalidParameter)
	}

	auditNodeIds := make([]eventlogger.NodeID, 0, len(auditPipelines))
	for _, p := range auditPipelines {
		gatedFilterNode := gated.Filter{
			Broker: e.broker,
		}
		e.flushableNodes = append(e.flushableNodes, &gatedFilterNode)
		gateId, err := NewId("gated-audit")
		if err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		p.gateId = eventlogger.NodeID(gateId)
		if err := e.broker.RegisterNode(p.gateId, &gatedFilterNode); err != nil {
			return nil, fmt.Errorf("%s: unable to register audit gated filter: %w", op, err)
		}

		pipeId, err := NewId(auditPipeline)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		err = e.broker.RegisterPipeline(eventlogger.Pipeline{
			EventType:  eventlogger.EventType(p.eventType),
			PipelineID: eventlogger.PipelineID(pipeId),
			// order of nodes is important!  gate (aggregate), then filter/format, then encrypt, then write to sink
			NodeIDs: []eventlogger.NodeID{p.gateId, p.encryptFilterId, p.fmtId, p.sinkId},
		})
		if err != nil {
			return nil, fmt.Errorf("%s: failed to register audit pipeline: %w", op, err)
		}
		auditNodeIds = append(auditNodeIds, p.sinkId)
	}

	observationNodeIds := make([]eventlogger.NodeID, 0, len(observationPipelines))
	for _, p := range observationPipelines {
		gatedFilterNode := gated.Filter{
			Broker: e.broker,
		}
		e.flushableNodes = append(e.flushableNodes, &gatedFilterNode)
		gateId, err := NewId("gated-observation")
		if err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		p.gateId = eventlogger.NodeID(gateId)
		if err := e.broker.RegisterNode(p.gateId, &gatedFilterNode); err != nil {
			return nil, fmt.Errorf("%s: unable to register audit gated filter: %w", op, err)
		}

		pipeId, err := NewId(observationPipeline)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		err = e.broker.RegisterPipeline(eventlogger.Pipeline{
			EventType:  eventlogger.EventType(p.eventType),
			PipelineID: eventlogger.PipelineID(pipeId),
			// order of nodes is important!  gate (aggregate), then filter/format, then write to sink
			NodeIDs: []eventlogger.NodeID{p.gateId, p.fmtId, p.sinkId},
		})
		if err != nil {
			return nil, fmt.Errorf("%s: failed to register observation pipeline: %w", op, err)
		}
		observationNodeIds = append(observationNodeIds, p.sinkId)
	}
	errNodeIds := make([]eventlogger.NodeID, 0, len(errPipelines))
	for _, p := range errPipelines {
		pipeId, err := NewId(errPipeline)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		err = e.broker.RegisterPipeline(eventlogger.Pipeline{
			EventType:  eventlogger.EventType(p.eventType),
			PipelineID: eventlogger.PipelineID(pipeId),
			// order of nodes is important!  filter/format, then write to sink
			NodeIDs: []eventlogger.NodeID{p.fmtId, p.sinkId},
		})
		if err != nil {
			return nil, fmt.Errorf("%s: failed to register err pipeline: %w", op, err)
		}
		errNodeIds = append(errNodeIds, p.sinkId)
	}
	sysNodeIds := make([]eventlogger.NodeID, 0, len(sysPipelines))
	for _, p := range sysPipelines {
		pipeId, err := NewId(sysPipeline)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		err = e.broker.RegisterPipeline(eventlogger.Pipeline{
			EventType:  eventlogger.EventType(p.eventType),
			PipelineID: eventlogger.PipelineID(pipeId),
			// order of nodes is important! filter/format, then write to sink
			NodeIDs: []eventlogger.NodeID{p.fmtId, p.sinkId},
		})
		if err != nil {
			return nil, fmt.Errorf("%s: failed to register sys pipeline: %w", op, err)
		}
		sysNodeIds = append(sysNodeIds, p.sinkId)
	}

	err := e.broker.SetSuccessThreshold(eventlogger.EventType(ObservationType), len(observationNodeIds))
	if err != nil {
		return nil, fmt.Errorf("%s: failed to set success threshold for observation events: %w", op, err)
	}
	err = e.broker.SetSuccessThreshold(eventlogger.EventType(AuditType), len(auditNodeIds))
	if err != nil {
		return nil, fmt.Errorf("%s: failed to set success threshold for audit events: %w", op, err)
	}
	err = e.broker.SetSuccessThreshold(eventlogger.EventType(ErrorType), len(errNodeIds))
	if err != nil {
		return nil, fmt.Errorf("%s: failed to set success threshold for error events: %w", op, err)
	}
	err = e.broker.SetSuccessThreshold(eventlogger.EventType(SystemType), len(sysNodeIds))
	if err != nil {
		return nil, fmt.Errorf("%s: failed to set success threshold for sysevents: %w", op, err)
	}

	e.auditPipelines = append(e.auditPipelines, auditPipelines...)
	e.errPipelines = append(e.errPipelines, errPipelines...)
	e.observationPipelines = append(e.observationPipelines, observationPipelines...)

	return e, nil
}

func newFmtFilterNode(serverName string, c SinkConfig, opt ...Option) (eventlogger.NodeID, eventlogger.Node, error) {
	const op = "newFmtFilterNode"
	if serverName == "" {
		return "", nil, fmt.Errorf("%s: missing server name: %w", op, ErrInvalidParameter)
	}
	opts := getOpts(opt...)
	var fmtId eventlogger.NodeID
	var fmtNode eventlogger.Node
	switch c.Format {
	case TextHclogSinkFormat, JSONHclogSinkFormat:
		id, err := NewId(string(c.Format))
		if err != nil {
			return "", nil, fmt.Errorf("%s: unable to generate id: %w", op, err)
		}
		fmtId = eventlogger.NodeID(id)

		fmtNode, err = newHclogFormatterFilter(c.Format == JSONHclogSinkFormat, WithAllow(c.AllowFilters...), WithDeny(c.DenyFilters...), WithAuditWrapper(opts.withAuditWrapper))
		if err != nil {
			return "", nil, fmt.Errorf("%s: %w", op, err)
		}

	default:
		id, err := NewId("cloudevents")
		if err != nil {
			return "", nil, fmt.Errorf("%s: unable to generate id: %w", op, err)
		}
		fmtId = eventlogger.NodeID(id)
		var sourceUrl *url.URL
		switch {
		case c.EventSourceUrl != "":
			sourceUrl, err = url.Parse(c.EventSourceUrl)
			if err != nil {
				return "", nil, fmt.Errorf("%s: invalid event source URL (%s): %w", op, c.EventSourceUrl, err)
			}
		default:
			s := fmt.Sprintf("https://hashicorp.com/boundary/%s", serverName)
			sourceUrl, err = url.Parse(s)
			if err != nil {
				return "", nil, fmt.Errorf("%s: invalid event source URL (%s): %w", op, s, err)
			}
		}
		fmtNode, err = newCloudEventsFormatterFilter(sourceUrl, cloudevents.Format(c.Format), WithAllow(c.AllowFilters...), WithDeny(c.DenyFilters...))
		if err != nil {
			return "", nil, fmt.Errorf("%s: %w", op, err)
		}
	}
	return fmtId, fmtNode, nil
}

func DefaultEventerConfig() *EventerConfig {
	return &EventerConfig{
		AuditEnabled:        false,
		TelemetryEnabled:    false,
		ObservationsEnabled: true,
		SysEventsEnabled:    true,
		Sinks:               []*SinkConfig{DefaultSink()},
	}
}

func DefaultSink() *SinkConfig {
	return &SinkConfig{
		Name:        "default",
		EventTypes:  []Type{EveryType},
		Format:      JSONSinkFormat,
		Type:        StderrSink,
		AuditConfig: DefaultAuditConfig(),
	}
}

func (e *Eventer) RotateAuditWrapper(ctx context.Context, newWrapper wrapping.Wrapper) error {
	const op = "event.(Eventer).RotateAuditWrapper"
	if newWrapper == nil {
		return fmt.Errorf("%s: missing wrapper: %w", op, ErrInvalidParameter)
	}
	for _, n := range e.auditWrapperNodes {
		switch w := n.(type) {
		case *hclogFormatterFilter:
			w.Rotate(newWrapper)
		case *cloudEventsFormatterFilter:
			w.Rotate(newWrapper)
		case *encrypt.Filter:
			w.Rotate(encrypt.WithWrapper(newWrapper))
		default:
			return fmt.Errorf("%s: unsupported node type (%s): %w", op, reflect.TypeOf(w), ErrInvalidParameter)
		}
	}
	return nil
}

// writeObservation writes/sends an Observation event.
func (e *Eventer) writeObservation(ctx context.Context, event *observation, _ ...Option) error {
	const op = "event.(Eventer).writeObservation"
	if event == nil {
		return fmt.Errorf("%s: missing event: %w", op, ErrInvalidParameter)
	}
	if !e.conf.ObservationsEnabled {
		return nil
	}
	err := e.retrySend(ctx, stdRetryCount, expBackoff{}, func() (eventlogger.Status, error) {
		if event.Header != nil {
			event.Header[RequestInfoField] = event.RequestInfo
			event.Header[VersionField] = event.Version
		}
		if event.Detail != nil {
			event.Detail[OpField] = string(event.Op)
		}
		return e.broker.Send(ctx, eventlogger.EventType(ObservationType), event)
	})
	if err != nil {
		e.logger.Error("encountered an error sending an observation event", "error:", err.Error())
		return fmt.Errorf("%s: %w", op, err)
	}
	return nil
}

// writeError writes/sends an Err event
func (e *Eventer) writeError(ctx context.Context, event *err, opt ...Option) error {
	const op = "event.(Eventer).writeError"
	if event == nil {
		return fmt.Errorf("%s: missing event: %w", op, ErrInvalidParameter)
	}
	if e.conf.ErrorEventsDisabled {
		return nil
	}
	opts := getOpts(opt...)
	if e.gated.Load() && !opts.withNoGateLocking {
		e.gatedQueueLock.Lock()
		defer e.gatedQueueLock.Unlock()
		if e.gated.Load() { // validate that it's still gated and we haven't just drained the queue
			e.gatedQueue = append(e.gatedQueue, &queuedEvent{
				ctx:   ctx,
				event: event,
			})
			return nil
		}
	}
	err := e.retrySend(ctx, stdRetryCount, expBackoff{}, func() (eventlogger.Status, error) {
		return e.broker.Send(ctx, eventlogger.EventType(ErrorType), event)
	})
	if err != nil {
		e.logger.Error("encountered an error sending an error event", "error:", err.Error())
		return fmt.Errorf("%s: %w", op, err)
	}
	return nil
}

// writeSysEvent writes/sends an sysEvent event
func (e *Eventer) writeSysEvent(ctx context.Context, event *sysEvent, opt ...Option) error {
	const op = "event.(Eventer).writeSysEvent"
	if event == nil {
		return fmt.Errorf("%s: missing event: %w", op, ErrInvalidParameter)
	}
	if !e.conf.SysEventsEnabled {
		return nil
	}
	opts := getOpts(opt...)
	if e.gated.Load() && !opts.withNoGateLocking {
		e.gatedQueueLock.Lock()
		defer e.gatedQueueLock.Unlock()
		if e.gated.Load() { // validate that it's still gated and we haven't just drained the queue
			e.gatedQueue = append(e.gatedQueue, &queuedEvent{
				ctx:   ctx,
				event: event,
			})
			return nil
		}
	}
	err := e.retrySend(ctx, stdRetryCount, expBackoff{}, func() (eventlogger.Status, error) {
		return e.broker.Send(ctx, eventlogger.EventType(SystemType), event)
	})
	if err != nil {
		e.logger.Error("encountered an error sending an sys event", "error:", err.Error())
		return fmt.Errorf("%s: %w", op, err)
	}
	return nil
}

// writeAudit writes/send an audit event
func (e *Eventer) writeAudit(ctx context.Context, event *audit, _ ...Option) error {
	const op = "event.(Eventer).writeAudit"
	if event == nil {
		return fmt.Errorf("%s: missing event: %w", op, ErrInvalidParameter)
	}
	if !e.conf.AuditEnabled {
		return nil
	}
	err := e.retrySend(ctx, stdRetryCount, expBackoff{}, func() (eventlogger.Status, error) {
		return e.broker.Send(ctx, eventlogger.EventType(AuditType), event)
	})
	if err != nil {
		e.logger.Error("encountered an error sending an audit event", "error:", err.Error())
		return fmt.Errorf("%s: %w", op, err)
	}
	return nil
}

// Reopen can used during a SIGHUP to reopen nodes, most importantly the underlying
// file sinks.
func (e *Eventer) Reopen() error {
	if e.broker != nil {
		return e.broker.Reopen(context.Background())
	}
	return nil
}

// FlushNodes will flush any of the eventer's flushable nodes.  This
// needs to be called whenever Boundary is stopping (aka shutting down).
func (e *Eventer) FlushNodes(ctx context.Context) error {
	const op = "event.(Eventer).FlushNodes"
	for _, n := range e.flushableNodes {
		if err := n.FlushAll(ctx); err != nil {
			return fmt.Errorf("%s: %w", op, err)
		}
	}
	return nil
}

// ReleaseGate releases queued events. If any event isn't successfully written,
// it remains in the queue and we could try a flush later.
func (e *Eventer) ReleaseGate() error {
	const op = "event.(Eventer).ReleaseGate"
	e.gatedQueueLock.Lock()
	defer e.gatedQueueLock.Unlock()

	// Don't gate anymore. By the time we hit this we will have the lock and be
	// guaranteed that nothing else will add onto the queue while we drain it.
	// Logic in the functions that add to the queue validate this boolean again
	// after they acquire the lock so running this function should fully drain
	// the events except in the case of an error.
	e.gated.Store(false)

	// Don't do anything if we're not gated and are fully drained
	if len(e.gatedQueue) == 0 && !e.gated.Load() {
		return nil
	}

	var totalErrs error
	for _, qe := range e.gatedQueue {
		var writeErr error
		if qe == nil {
			continue // we may have already sent this but gotten errors later
		}
		ctx, cancel := newSendCtx(qe.ctx)
		if cancel != nil {
			defer cancel()
		}
		var queuedOp string
		switch t := qe.event.(type) {
		case *sysEvent:
			queuedOp = "system"
			writeErr = e.writeSysEvent(ctx, t, WithNoGateLocking(true))
		case *err:
			queuedOp = "error"
			writeErr = e.writeError(ctx, t, WithNoGateLocking(true))
		default:
			// Have no idea what this is and shouldn't have gotten in here to
			// begin with, so just continue, and log it
			writeErr = fmt.Errorf("unknown event type %T", t)
		}
		if writeErr != nil {
			totalErrs = errors.Join(fmt.Errorf("in %s, error sending queued %s event: %w", op, queuedOp, writeErr))
		}
	}
	e.gatedQueue = nil
	return totalErrs
}

// StandardLogger will create *log.Logger that will emit events through this
// Logger.  This allows packages that require the stdlib log to emit events
// instead.
func (e *Eventer) StandardLogger(ctx context.Context, loggerName string, typ Type) (*log.Logger, error) {
	const op = "event.(Eventer).StandardLogger"
	if e == nil {
		return nil, fmt.Errorf("%s: nil eventer: %w", op, ErrInvalidParameter)
	}
	if ctx == nil {
		return nil, fmt.Errorf("%s: missing context: %w", op, ErrInvalidParameter)
	}
	if typ == "" {
		return nil, fmt.Errorf("%s: missing type: %w", op, ErrInvalidParameter)
	}
	w, err := e.StandardWriter(ctx, typ)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return log.New(w, loggerName, 0), nil
}

// StandardWriter will create an io.Writer that will emit events through this
// io.Writer.
func (e *Eventer) StandardWriter(ctx context.Context, typ Type) (io.Writer, error) {
	const op = "event.(Eventer).StandardErrorWriter"
	if e == nil {
		return nil, fmt.Errorf("%s: nil eventer: %w", op, ErrInvalidParameter)
	}
	if ctx == nil {
		return nil, fmt.Errorf("%s: missing context: %w", op, ErrInvalidParameter)
	}
	if typ == "" {
		return nil, fmt.Errorf("%s: missing type: %w", op, ErrInvalidParameter)
	}
	if err := typ.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	ctx, err := NewEventerContext(ctx, e)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return &logAdapter{
		ctxWithEventer: ctx,
		e:              e,
		emitEventType:  typ,
	}, nil
}

type logAdapter struct {
	ctxWithEventer context.Context
	e              *Eventer
	emitEventType  Type
}

// Write satisfies the io.Writer interface and will take the data, infer the
// type of event and then emit an event.
func (s *logAdapter) Write(data []byte) (int, error) {
	const op = "event.(stdlogAdapter).Write"
	if s == nil {
		return 0, fmt.Errorf("%s: nil log adapter: %w", op, ErrInvalidParameter)
	}
	var caller Op
	pc, _, _, ok := runtime.Caller(1)
	details := runtime.FuncForPC(pc)
	if ok && details != nil {
		caller = Op(details.Name())
	} else {
		caller = "unknown operation"
	}

	str := string(bytes.TrimRight(data, " \t\n"))
	switch s.emitEventType {
	case ErrorType, SystemType:
		if err := s.send(s.emitEventType, caller, str); err != nil {
			return 0, fmt.Errorf("%s: %w", op, err)
		}
	default:
		t, str := s.pickType(str)
		if err := s.send(t, caller, str); err != nil {
			return 0, fmt.Errorf("%s: %w", op, err)
		}
	}

	return len(data), nil
}

func (s *logAdapter) send(typ Type, caller Op, str string) error {
	const op = "events.(stdlogAdapter).send"
	if typ == "" {
		return fmt.Errorf("%s: type is missing: %w", op, ErrInvalidParameter)
	}
	if caller == "" {
		return fmt.Errorf("%s: missing caller: %w", op, ErrInvalidParameter)
	}
	switch typ {
	case ErrorType:
		WriteError(s.ctxWithEventer, caller, errors.New(str))
		return nil
	case SystemType:
		WriteSysEvent(s.ctxWithEventer, caller, str)
		return nil
	default:
		return fmt.Errorf("%s: unsupported event type %s: %w", op, typ, ErrInvalidParameter)
	}
}

func (s *logAdapter) pickType(str string) (Type, string) {
	switch {
	case strings.HasPrefix(str, "[DEBUG]"):
		return SystemType, strings.TrimSpace(str[7:])
	case strings.HasPrefix(str, "[TRACE]"):
		return SystemType, strings.TrimSpace(str[7:])
	case strings.HasPrefix(str, "[INFO]"):
		return SystemType, strings.TrimSpace(str[6:])
	case strings.HasPrefix(str, "[WARN]"):
		return SystemType, strings.TrimSpace(str[6:])
	case strings.HasPrefix(str, "[ERROR]"):
		return ErrorType, strings.TrimSpace(str[7:])
	case strings.HasPrefix(str, "[ERR]"):
		return ErrorType, strings.TrimSpace(str[5:])
	default:
		return SystemType, str
	}
}

func isNil(i any) bool {
	if i == nil {
		return true
	}
	switch reflect.TypeOf(i).Kind() {
	case reflect.Ptr, reflect.Map, reflect.Array, reflect.Chan, reflect.Slice:
		return reflect.ValueOf(i).IsNil()
	}
	return false
}
