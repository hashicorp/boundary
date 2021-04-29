package logger

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/hashicorp/eventlogger"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/shared-secure-libs/gatedwriter"
)

type key int

var OBSkey key

const testEvent eventlogger.EventType = "test"

type TestEvent struct {
	Timestamp time.Time
	Stage     string
	ID        string
}

type Eventer struct {
	broker *eventlogger.Broker
	ctx    context.Context
	sink   EventSink
}

type EventSink struct {
	Type     string
	Format   string
	Path     string
	FileName string
}

func EventReq(req *http.Request) interface{} {
	payload := TestEvent{
		Timestamp: time.Now(),
		Stage:     "OperationStart",
	}

	payloadID, err := uuid.GenerateUUID()
	if err != nil {
		fmt.Errorf("could not audit error %v request %v ", err, payload)
		return payload
	}
	payload.ID = payloadID

	return payload

}

func (e *Eventer) WriteEvent(eventType string, payload interface{}, ctx context.Context) error {
	et := eventlogger.EventType(eventType)
	fmt.Println("Hello from Write Event")
	_, err := e.broker.Send(ctx, et, payload)
	if err != nil {
		return fmt.Errorf("failed in write, %w", err)
	}
	return nil
}

func NewEventer(config EventSink) (*Eventer, error) {
	var e Eventer

	//create a broker
	broker := *eventlogger.NewBroker()

	// add it to the eventer
	e = Eventer{
		sink: config,
	}

	//get the file sink node
	nodes := e.Nodes()

	//register node with broker
	for _, n := range nodes {
		node := n.v.(eventlogger.Node)
		err1 := broker.RegisterNode(n.id, node)
		if err1 != nil {
			fmt.Println("unable to register node")
			break
		}
		fmt.Printf("node is of %v", node.Type())
	}

	//associate node(s) with pipeline
	sinkpipe := NewPipeline(nodes)
	err := broker.RegisterPipeline(sinkpipe)
	if err != nil {
		fmt.Errorf("broke registering pipe")
	}

	e.broker = &broker
	return &e, nil
}

type Node struct {
	id eventlogger.NodeID
	v  interface{} // *eventlogger.Node
}

func NewPipeline(nodes []Node) eventlogger.Pipeline {

	// generate uuid for pipeline id
	uID, err := uuid.GenerateUUID()
	if err != nil {
		fmt.Errorf("unable to generate uuid error %v", err)
	}
	id := eventlogger.PipelineID(uID)

	var nIDs []eventlogger.NodeID
	for _, n := range nodes {
		nIDs = append(nIDs, n.id)
	}

	return eventlogger.Pipeline{
		PipelineID: id,
		EventType:  "test",
		NodeIDs:    nIDs,
	}

}

func (e *Eventer) Nodes() []Node {
	nodes := make([]Node, 0)
	var fileSinkNode eventlogger.FileSink
	fileSinkID, err := nodeUUID()
	if err != nil {
		fmt.Errorf("unable to generate uuid error %w", err)
	}
	fileSinkNode = eventlogger.FileSink{
		Path:     e.sink.Path,
		FileName: e.sink.FileName,
	}
	nodes = append(nodes, Node{
		id: fileSinkID,
		v:  &fileSinkNode,
	})
	return nodes
}

func nodeUUID() (eventlogger.NodeID, error) {
	id, err := uuid.GenerateUUID()
	nodeID := eventlogger.NodeID(id)
	if err != nil {
		return "", err
	}
	return nodeID, nil
}

//logger below
//NOTE: should move this into observabaility
//
type OBSCollector struct {
	logger hclog.Logger
	writer *gatedwriter.Writer
}

func (obs *OBSCollector) Log(msg string) {
	obs.logger.Info(msg)
}

func (obs *OBSCollector) Flush() {
	obs.writer.Flush()
}

//(schristoff): add new obsev. context
func NewObserv(ctx context.Context, _ hclog.Logger) context.Context {
	writer := gatedwriter.NewWriter(os.Stdout)
	opts := &hclog.LoggerOptions{
		Name:   "test",
		Output: writer,
	}
	logger := hclog.New(opts)

	logger.Info("logger created")
	return context.WithValue(ctx, OBSkey, &OBSCollector{
		logger: logger,
		writer: writer,
	})
}

//ObservFromContext returns the OBSCollector from a given context
func ObservFromContext(ctx context.Context) *OBSCollector {
	v, _ := ctx.Value(OBSkey).(*OBSCollector)
	return v
}
