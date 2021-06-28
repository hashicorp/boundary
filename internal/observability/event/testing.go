package event

import (
	"context"
	"io/ioutil"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/gen/controller/api/resources/groups"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/eventlogger"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var testSysEventerLock sync.Mutex

// TestResetSysEventer will reset event.syseventer to an uninitialized state.
func TestResetSystEventer(t *testing.T) {
	t.Helper()
	testSysEventerLock.Lock()
	defer testSysEventerLock.Unlock()
	sysEventerOnce = sync.Once{}
	sysEventer = nil
}

type TestConfig struct {
	EventerConfig EventerConfig
	AllEvents     *os.File
	ErrorEvents   *os.File
}

// TestEventerConfig creates a test config and registers a cleanup func for its
// test tmp files.
func TestEventerConfig(t *testing.T, testName string, opt ...Option) TestConfig {
	t.Helper()
	require := require.New(t)
	tmpAllFile, err := ioutil.TempFile("./", "tmp-all-events-"+testName)
	require.NoError(err)

	tmpErrFile, err := ioutil.TempFile("./", "tmp-errors-"+testName)
	require.NoError(err)

	t.Cleanup(func() {
		os.Remove(tmpAllFile.Name())
		os.Remove(tmpErrFile.Name())
	})

	c := TestConfig{
		EventerConfig: EventerConfig{
			ObservationsEnabled: true,
			ObservationDelivery: Enforced,
			AuditEnabled:        true,
			AuditDelivery:       Enforced,
			Sinks: []SinkConfig{
				{
					Name:       "every-type-file-sink",
					SinkType:   FileSink,
					EventTypes: []Type{EveryType},
					Format:     JSONSinkFormat,
					Path:       "./",
					FileName:   tmpAllFile.Name(),
				},
				{
					Name:       "stdout",
					SinkType:   StdoutSink,
					EventTypes: []Type{EveryType},
					Format:     JSONSinkFormat,
				},
				{
					Name:       "err-file-sink",
					SinkType:   FileSink,
					EventTypes: []Type{ErrorType},
					Format:     JSONSinkFormat,
					Path:       "./",
					FileName:   tmpErrFile.Name(),
				},
			},
		},
		AllEvents:   tmpAllFile,
		ErrorEvents: tmpErrFile,
	}
	opts := getOpts(opt...)
	if opts.withAuditSink {
		tmpFile, err := ioutil.TempFile("./", "tmp-audit-"+testName)
		require.NoError(err)
		t.Cleanup(func() {
			os.Remove(tmpFile.Name())
		})
		c.EventerConfig.Sinks = append(c.EventerConfig.Sinks, SinkConfig{
			Name:       "audit-file-sink",
			SinkType:   FileSink,
			EventTypes: []Type{AuditType},
			Format:     JSONSinkFormat,
			Path:       "./",
			FileName:   tmpFile.Name(),
		})
	}
	if opts.withObservationSink {
		tmpFile, err := ioutil.TempFile("./", "tmp-observation-"+testName)
		require.NoError(err)
		t.Cleanup(func() {
			os.Remove(tmpFile.Name())
		})
		c.EventerConfig.Sinks = append(c.EventerConfig.Sinks, SinkConfig{
			Name:       "err-observation-sink",
			SinkType:   FileSink,
			EventTypes: []Type{ObservationType},
			Format:     JSONSinkFormat,
			Path:       "./",
			FileName:   tmpFile.Name(),
		})
	}
	if opts.withSysSink {
		tmpFile, err := ioutil.TempFile("./", "tmp-sysevents-"+testName)
		require.NoError(err)
		t.Cleanup(func() {
			os.Remove(tmpFile.Name())
		})
		c.EventerConfig.Sinks = append(c.EventerConfig.Sinks, SinkConfig{
			Name:       "err-sysevents-sink",
			SinkType:   FileSink,
			EventTypes: []Type{SystemType},
			Format:     JSONSinkFormat,
			Path:       "./",
			FileName:   tmpFile.Name(),
		})
	}
	return c
}

// TestRequestInfo provides a test RequestInfo
func TestRequestInfo(t *testing.T) *RequestInfo {
	t.Helper()
	return &RequestInfo{
		Id:       "test-request-info",
		Method:   "POST",
		Path:     "/test/request/info",
		PublicId: "public-id",
	}
}

func testAuth(t *testing.T) *Auth {
	t.Helper()
	return &Auth{
		UserEmail: "test-auth@example.com",
		UserName:  "test-auth-user-name",
	}
}

func testRequest(t *testing.T) *Request {
	t.Helper()
	return &Request{
		Operation: "op",
		Endpoint:  "/group/<id>",
		Details: &pbs.GetGroupRequest{
			Id: "group-id",
		},
	}
}

func testResponse(t *testing.T) *Response {
	t.Helper()
	return &Response{
		StatusCode: 200,
		Details: &pbs.GetGroupResponse{
			Item: &groups.Group{
				Id:      "group-id",
				ScopeId: "org-id",
				Name: &wrapperspb.StringValue{
					Value: "group-name",
				},
			},
		},
	}
}

// testWithBroker is an unexported and a test option for passing in an optional broker
func testWithBroker(b broker) Option {
	return func(o *options) {
		o.withBroker = b
	}
}

// testWithObservationSink is an unexported and a test option
func testWithObservationSink() Option {
	return func(o *options) {
		o.withObservationSink = true
	}
}

// testWithAuditSink is an unexported and a test option
func testWithAuditSink() Option {
	return func(o *options) {
		o.withAuditSink = true
	}
}

// testWithSysSink is an unexported and a test option
func testWithSysSink() Option {
	return func(o *options) {
		o.withSysSink = true
	}
}

type testMockBroker struct {
	reopened          bool
	stopTimeAt        time.Time
	registeredNodeIds []eventlogger.NodeID
	successThresholds map[eventlogger.EventType]int
	pipelines         []eventlogger.Pipeline

	errorOnSend error
}

func (b *testMockBroker) Reopen(ctx context.Context) error {
	b.reopened = true
	return nil
}

func (b *testMockBroker) RegisterPipeline(def eventlogger.Pipeline) error {
	b.pipelines = append(b.pipelines, def)
	return nil
}

func (b *testMockBroker) Send(ctx context.Context, t eventlogger.EventType, payload interface{}) (eventlogger.Status, error) {
	if b.errorOnSend != nil {
		return eventlogger.Status{}, b.errorOnSend
	}
	return eventlogger.Status{}, nil
}

func (b *testMockBroker) StopTimeAt(t time.Time) {
	b.stopTimeAt = t
}

func (b *testMockBroker) RegisterNode(id eventlogger.NodeID, node eventlogger.Node) error {
	b.registeredNodeIds = append(b.registeredNodeIds, id)
	return nil
}

func (b *testMockBroker) SetSuccessThreshold(t eventlogger.EventType, successThreshold int) error {
	if b.successThresholds == nil {
		b.successThresholds = map[eventlogger.EventType]int{}
	}
	b.successThresholds[t] = successThreshold
	return nil
}
