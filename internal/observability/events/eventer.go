package event

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/eventlogger"
	"github.com/hashicorp/go-hclog"
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
)

type SinkType string          // SinkType defines the type of sink in a config stanza (file, stdout)
type SinkFormat string        // SinkFormat defines the formatting for a sink in a config file stanza (json)
type DeliveryGuarantee string // DeliveryGuarantee defines the guarantees around delivery of an event type within config

const (
	StdoutSink          SinkType          = "stdout"               // StdoutSink is written to stdout
	FileSink            SinkType          = "file"                 // FileSink is written to a file
	JSONSinkFormat      SinkFormat        = "json"                 // JSONSinkFormat means the event is formatted as JSON
	Enforced            DeliveryGuarantee = "enforced"             // Enforced means that a delivery guarantee is enforced
	BestEffort          DeliveryGuarantee = "best-effort"          // BestEffort means that a best effort will be made to deliver an event
	AuditPipeline                         = "audit-pipeline"       // AuditPipeline is a pipeline for audit events
	ObservationPipeline                   = "observation-pipeline" // ObservationPipeline is a pipeline for observation events
	ErrPipeline                           = "err-pipeline"         // ErrPipeline is a pipeline for error events
)

// flushable defines an interface that all eventlogger Nodes must implement if
// they are "flushable"
type flushable interface {
	FlushAll(ctx context.Context) error
}

// broker defines an interface for an eventlogger Broker... which will allow us
// to substitute our our testing broker when needed to write tests for things
// like event send retrying.
type broker interface {
	Send(ctx context.Context, t eventlogger.EventType, payload interface{}) (eventlogger.Status, error)
	Reopen(ctx context.Context) error
}

// Eventer provides a method to send events to pipelines of sinks
type Eventer struct {
	broker         broker
	flushableNodes []flushable
	conf           EventerConfig
	logger         hclog.Logger
}

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

// EventerConfig supplies all the configuration needed to create/config an Eventer.
type EventerConfig struct {
	AuditDelivery       DeliveryGuarantee // AuditDelivery specifies the delivery guarantees for audit events (enforced or best effort).
	ObservationDelivery DeliveryGuarantee // ObservationDelivery specifies the delivery guarantees for observation events (enforced or best effort).
	AuditEnabled        bool              // AuditEnabled specifies if audit events should be emitted.
	ObservationsEnabled bool              // ObservationsEnabled specifies if observation events should be emitted.
	Sinks               []SinkConfig      // Sinks are all the configured sinks
}

var sysEventer *Eventer      // sysEventer is the system-wide Eventer
var sysEventerOnce sync.Once // sysEventerOnce ensures that the system-wide Eventer is only initialized once.

// InitSysEventer provides a mechanism to initialize a "system wide" eventer
// singleton for Boundary
func InitSysEventer(log hclog.Logger, c EventerConfig) error {
	const op = "event.InitSysEventer"
	if log == nil {
		return errors.New(errors.InvalidParameter, op, "missing hclog")
	}
	// the order of operations is important here.  we want to determine if
	// there's an error before setting the singleton sysEventer which can only
	// be done one time.
	eventer, err := NewEventer(log, c)
	if err != nil {
		return errors.Wrap(err, op)
	}
	sysEventerOnce.Do(func() {
		sysEventer = eventer
	})
	return nil
}

// SysEventer returns the "system wide" eventer for Boundary.
func SysEventer() *Eventer {
	return sysEventer
}

// NewEventer creates a new Eventer using the config
func NewEventer(log hclog.Logger, c EventerConfig, opt ...Option) (*Eventer, error) {
	const op = "event.NewEventer"
	if log == nil {
		return nil, errors.New(errors.InvalidParameter, op, "missing logger")
	}

	type pipeline struct {
		eventType Type
		fmtId     eventlogger.NodeID
		sinkId    eventlogger.NodeID
	}
	var flushableNodes []flushable
	var auditPipelines, observationPipelines, errPipelines []pipeline

	broker := eventlogger.NewBroker()
	opts := getOpts(opt...)
	if !opts.withNow.IsZero() {
		broker.StopTimeAt(opts.withNow)
	}

	// Create JSONFormatter node
	id, err := newId("json")
	if err != nil {
		return nil, errors.Wrap(err, op)
	}
	jsonfmtId := eventlogger.NodeID(id)
	fmtNode := &eventlogger.JSONFormatter{}
	err = broker.RegisterNode(jsonfmtId, fmtNode)
	if err != nil {
		return nil, errors.Wrap(err, "failed to register json node")
	}

	// if there are no sinks in config, then we'll default to just one stdout
	// sink.
	if len(c.Sinks) == 0 {
		c.Sinks = append(c.Sinks, SinkConfig{
			Name:       "default",
			EventTypes: []Type{EveryType},
			Format:     JSONSinkFormat,
			SinkType:   StdoutSink,
		})
	}

	for _, s := range c.Sinks {
		var sinkId eventlogger.NodeID
		var sinkNode eventlogger.Node
		switch s.SinkType {
		case StdoutSink:
			sinkNode = &eventlogger.WriterSink{
				Format: string(s.Format),
				Writer: os.Stdout,
			}
			id, err = newId("stdout")
			if err != nil {
				return nil, errors.Wrap(err, op)
			}
			sinkId = eventlogger.NodeID(id)
		default:
			sinkNode = &eventlogger.FileSink{
				Format:      string(s.Format),
				Path:        s.Path,
				FileName:    s.FileName,
				MaxBytes:    s.RotateBytes,
				MaxDuration: s.RotateDuration,
				MaxFiles:    s.RotateMaxFiles,
			}
			id, err = newId(fmt.Sprintf("file_%s_%s_", s.Path, s.FileName))
			if err != nil {
				return nil, errors.Wrap(err, op)
			}
			sinkId = eventlogger.NodeID(id)
		}
		err = broker.RegisterNode(sinkId, sinkNode)
		if err != nil {
			return nil, errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("failed to register sink node %s", sinkId)))
		}
		var addToAudit, addToObservation, addToErr bool
		for _, t := range s.EventTypes {
			switch t {
			case EveryType:
				addToAudit = true
				addToObservation = true
				addToErr = true
			case ErrorType:
				addToErr = true
			case AuditType:
				addToAudit = true
			case ObservationType:
				addToObservation = true
			}
		}
		if addToAudit {
			auditPipelines = append(auditPipelines, pipeline{
				eventType: AuditType,
				fmtId:     jsonfmtId,
				sinkId:    sinkId,
			})
		}
		if addToObservation {
			observationPipelines = append(observationPipelines, pipeline{
				eventType: ObservationType,
				fmtId:     jsonfmtId,
				sinkId:    sinkId,
			})
		}
		if addToErr {
			errPipelines = append(errPipelines, pipeline{
				eventType: ErrorType,
				fmtId:     jsonfmtId,
				sinkId:    sinkId,
			})
		}
	}
	if c.AuditEnabled && len(auditPipelines) == 0 {
		return nil, errors.New(errors.InvalidParameter, op, "audit events enabled but no sink defined for it")
	}
	if c.ObservationsEnabled && len(observationPipelines) == 0 {
		return nil, errors.New(errors.InvalidParameter, op, "observation events enabled but no sink defined for it")
	}

	auditNodeIds := make([]eventlogger.NodeID, 0, len(auditPipelines))
	for _, p := range auditPipelines {
		gatedFilterNode := eventlogger.GatedFilter{}
		flushableNodes = append(flushableNodes, &gatedFilterNode)
		gateId, err := newId("gated-audit")
		if err != nil {
			return nil, errors.Wrap(err, op)
		}
		gatedFilterNodeId := eventlogger.NodeID(gateId)
		if err := broker.RegisterNode(gatedFilterNodeId, &gatedFilterNode); err != nil {
			return nil, errors.Wrap(err, op, errors.WithMsg("unable to register audit gated filter"))
		}

		pipeId, err := newId(AuditPipeline)
		if err != nil {
			return nil, errors.Wrap(err, op)
		}
		err = broker.RegisterPipeline(eventlogger.Pipeline{
			EventType:  eventlogger.EventType(p.eventType),
			PipelineID: eventlogger.PipelineID(pipeId),
			NodeIDs:    []eventlogger.NodeID{gatedFilterNodeId, p.fmtId, p.sinkId},
		})
		if err != nil {
			return nil, errors.Wrap(err, "failed to register audit pipeline")
		}
		auditNodeIds = append(auditNodeIds, p.sinkId)
	}
	observationNodeIds := make([]eventlogger.NodeID, 0, len(observationPipelines))
	for _, p := range observationPipelines {
		gatedFilterNode := eventlogger.GatedFilter{}
		flushableNodes = append(flushableNodes, &gatedFilterNode)
		gateId, err := newId("gated-audit")
		if err != nil {
			return nil, errors.Wrap(err, op)
		}
		gatedFilterNodeId := eventlogger.NodeID(gateId)
		if err := broker.RegisterNode(gatedFilterNodeId, &gatedFilterNode); err != nil {
			return nil, errors.Wrap(err, op, errors.WithMsg("unable to register audit gated filter"))
		}

		pipeId, err := newId(ObservationPipeline)
		if err != nil {
			return nil, errors.Wrap(err, op)
		}
		err = broker.RegisterPipeline(eventlogger.Pipeline{
			EventType:  eventlogger.EventType(p.eventType),
			PipelineID: eventlogger.PipelineID(pipeId),
			NodeIDs:    []eventlogger.NodeID{gatedFilterNodeId, p.fmtId, p.sinkId},
		})
		if err != nil {
			return nil, errors.Wrap(err, "failed to register observation pipeline")
		}
		observationNodeIds = append(observationNodeIds, p.sinkId)
	}
	errNodeIds := make([]eventlogger.NodeID, 0, len(errPipelines))
	for _, p := range errPipelines {
		pipeId, err := newId(ErrPipeline)
		if err != nil {
			return nil, errors.Wrap(err, op)
		}
		err = broker.RegisterPipeline(eventlogger.Pipeline{
			EventType:  eventlogger.EventType(p.eventType),
			PipelineID: eventlogger.PipelineID(pipeId),
			NodeIDs:    []eventlogger.NodeID{p.fmtId, p.sinkId},
		})
		if err != nil {
			return nil, errors.Wrap(err, "failed to register err pipeline")
		}
		errNodeIds = append(errNodeIds, p.sinkId)
	}

	// TODO(jimlambrt) go-eventlogger SetSuccessThreshold currently does not
	// specify which sink passed and which hasn't so we are unable to
	// support multiple sinks with different delivery guarantees
	if c.AuditDelivery == Enforced {
		err = broker.SetSuccessThreshold(eventlogger.EventType(AuditType), len(auditNodeIds))
		if err != nil {
			return nil, errors.Wrap(err, "failed to set success threshold for audit events")
		}
	}
	if c.ObservationDelivery == Enforced {
		err = broker.SetSuccessThreshold(eventlogger.EventType(ObservationType), len(observationNodeIds))
		if err != nil {
			return nil, errors.Wrap(err, "failed to set success threshold for observation events")
		}
	}
	// always enforce delivery of errors
	err = broker.SetSuccessThreshold(eventlogger.EventType(ErrorType), len(errNodeIds))
	if err != nil {
		return nil, errors.Wrap(err, "failed to set success threshold for error events")
	}

	return &Eventer{
		logger:         log,
		conf:           c,
		broker:         broker,
		flushableNodes: flushableNodes,
	}, nil
}

// writeObservation writes/sends an Observation event.
func (e *Eventer) writeObservation(ctx context.Context, event *observation) error {
	const op = "event.(Eventer).WriteObservation"
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
		return e.broker.Send(ctx, eventlogger.EventType(ObservationType), event.SimpleGatedPayload)
	})
	if err != nil {
		e.logger.Error("encountered an error sending an observation event", "error:", err.Error())
		return errors.Wrap(err, op)
	}
	return nil
}

// writeError writes/sends an Err event
func (e *Eventer) writeError(ctx context.Context, event *err) error {
	const op = "event.(Eventer).WriteError"
	err := e.retrySend(ctx, stdRetryCount, expBackoff{}, func() (eventlogger.Status, error) {
		return e.broker.Send(ctx, eventlogger.EventType(ErrorType), event)
	})
	if err != nil {
		e.logger.Error("encountered an error sending an error event", "error:", err.Error())
		return errors.Wrap(err, op)
	}
	return nil
}

// writeAudit writes/send an audit event
func (e *Eventer) writeAudit(ctx context.Context, event *Audit) error {
	const op = "event.(Eventer).WriteAudit"
	if !e.conf.AuditEnabled {
		return nil
	}
	err := e.retrySend(ctx, stdRetryCount, expBackoff{}, func() (eventlogger.Status, error) {
		return e.broker.Send(ctx, eventlogger.EventType(AuditType), event)
	})
	if err != nil {
		e.logger.Error("encountered an error sending an audit event", "error:", err.Error())
		return errors.Wrap(err, op)
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
	const op = "event.(Eventer).FlushAll"
	for _, n := range e.flushableNodes {
		if err := n.FlushAll(ctx); err != nil {
			return errors.Wrap(err, op)
		}
	}
	return nil
}
