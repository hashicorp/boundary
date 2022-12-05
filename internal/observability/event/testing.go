package event

import (
	"context"
	"io/ioutil"
	"os"
	"sync"
	"testing"
	"time"

	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/groups"
	"github.com/hashicorp/eventlogger"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// TestWithoutEventing allows the caller to "disable" all eventing for a test.
// You must not run the test in parallel (no calls to t.Parallel) since the
// function relies on modifying the system wide default eventer.
func TestWithoutEventing(t testing.TB) *Eventer {
	t.Helper()
	require := require.New(t)
	testConfig := EventerConfig{
		AuditEnabled:        false,
		ObservationsEnabled: false,
		SysEventsEnabled:    false,
	}
	testLock := &sync.Mutex{}
	testLogger := hclog.New(&hclog.LoggerOptions{
		Mutex:  testLock,
		Output: ioutil.Discard,
	})
	testEventer, err := NewEventer(testLogger, testLock, "TestWithoutEventing", testConfig, withNoDefaultSink(t))
	require.NoError(err)

	require.NoError(InitSysEventer(testLogger, testLock, "TestWithoutEventing", WithEventer(testEventer)))
	return testEventer
}

// TestGetEventerConfig is a test accessor for the eventer's config
func TestGetEventerConfig(t testing.TB, e *Eventer) EventerConfig {
	t.Helper()
	return e.conf
}

// TestResetSysEventer will reset event.syseventer to an uninitialized state.
func TestResetSystEventer(t testing.TB) {
	t.Helper()
	sysEventerLock.Lock()
	defer sysEventerLock.Unlock()
	sysEventer = nil
}

type TestConfig struct {
	EventerConfig     EventerConfig
	AllEvents         *os.File
	ErrorEvents       *os.File
	ObservationEvents *os.File
	AuditEvents       *os.File
}

// TestEventerConfig creates a test config and registers a cleanup func for its
// test tmp files.
func TestEventerConfig(t testing.TB, testName string, opt ...Option) TestConfig {
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

	opts := getOpts(opt...)
	if opts.withSinkFormat == "" {
		opts.withSinkFormat = JSONSinkFormat
	}

	c := TestConfig{
		EventerConfig: EventerConfig{
			ObservationsEnabled: true,
			AuditEnabled:        true,
			Sinks: []*SinkConfig{
				{
					Name:       "every-type-file-sink",
					Type:       FileSink,
					EventTypes: []Type{EveryType},
					Format:     opts.withSinkFormat,
					FileConfig: &FileSinkTypeConfig{
						Path:     "./",
						FileName: tmpAllFile.Name(),
					},
					AuditConfig: DefaultAuditConfig(),
				},
				{
					Name:        "stderr",
					Type:        StderrSink,
					EventTypes:  []Type{EveryType},
					Format:      opts.withSinkFormat,
					AuditConfig: DefaultAuditConfig(),
				},
				{
					Name:       "err-file-sink",
					Type:       FileSink,
					EventTypes: []Type{ErrorType},
					Format:     opts.withSinkFormat,
					FileConfig: &FileSinkTypeConfig{
						Path:     "./",
						FileName: tmpErrFile.Name(),
					},
				},
			},
		},
		AllEvents:   tmpAllFile,
		ErrorEvents: tmpErrFile,
	}
	if opts.withAuditSink {
		tmpFile, err := ioutil.TempFile("./", "tmp-audit-"+testName)
		require.NoError(err)
		t.Cleanup(func() {
			os.Remove(tmpFile.Name())
		})
		c.EventerConfig.Sinks = append(c.EventerConfig.Sinks, &SinkConfig{
			Name:       "audit-file-sink",
			Type:       FileSink,
			EventTypes: []Type{AuditType},
			Format:     opts.withSinkFormat,
			FileConfig: &FileSinkTypeConfig{
				Path:     "./",
				FileName: tmpFile.Name(),
			},
			AuditConfig: DefaultAuditConfig(),
		})
		c.AuditEvents = tmpFile
	}
	if opts.withObservationSink {
		tmpFile, err := ioutil.TempFile("./", "tmp-observation-"+testName)
		require.NoError(err)
		t.Cleanup(func() {
			os.Remove(tmpFile.Name())
		})
		c.EventerConfig.Sinks = append(c.EventerConfig.Sinks, &SinkConfig{
			Name:       "err-observation-sink",
			Type:       FileSink,
			EventTypes: []Type{ObservationType},
			Format:     opts.withSinkFormat,
			FileConfig: &FileSinkTypeConfig{
				Path:     "./",
				FileName: tmpFile.Name(),
			},
		})
		c.ObservationEvents = tmpFile
	}
	if opts.withSysSink {
		tmpFile, err := ioutil.TempFile("./", "tmp-sysevents-"+testName)
		require.NoError(err)
		t.Cleanup(func() {
			os.Remove(tmpFile.Name())
		})
		c.EventerConfig.Sinks = append(c.EventerConfig.Sinks, &SinkConfig{
			Name:       "err-sysevents-sink",
			Type:       FileSink,
			EventTypes: []Type{SystemType},
			Format:     opts.withSinkFormat,
			FileConfig: &FileSinkTypeConfig{
				Path:     "./",
				FileName: tmpFile.Name(),
			},
		})
	}
	return c
}

// TestRequestInfo provides a test RequestInfo
func TestRequestInfo(t testing.TB) *RequestInfo {
	t.Helper()
	return &RequestInfo{
		EventId:  "test-event-id",
		Id:       "test-request-info",
		Method:   "POST",
		Path:     "/test/request/info",
		PublicId: "public-id",
	}
}

func testAuth(t testing.TB) *Auth {
	t.Helper()
	return &Auth{
		UserEmail: "test-auth@example.com",
		UserName:  "test-auth-user-name",
	}
}

func testRequest(t testing.TB) *Request {
	t.Helper()
	return &Request{
		Operation: "op",
		Endpoint:  "/group/<id>",
		Details: &pbs.GetGroupRequest{
			Id: "group-id",
		},
	}
}

func testResponse(t testing.TB) *Response {
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

// TestWithBroker is an unexported and a test option for passing in an optional broker
func TestWithBroker(t testing.TB, b broker) Option {
	t.Helper()
	return func(o *options) {
		o.withBroker = b
	}
}

// TestWithObservationSink is a test option
func TestWithObservationSink(t testing.TB) Option {
	t.Helper()
	return func(o *options) {
		o.withObservationSink = true
	}
}

// TestWithAuditSink is a test option
func TestWithAuditSink(t testing.TB) Option {
	t.Helper()
	return func(o *options) {
		o.withAuditSink = true
	}
}

// TestWithSysSink is a test option
func TestWithSysSink(t testing.TB) Option {
	t.Helper()
	return func(o *options) {
		o.withSysSink = true
	}
}

// withNoDefaultSink is an unexported test option
func withNoDefaultSink(t testing.TB) Option {
	t.Helper()
	return func(o *options) {
		o.withNoDefaultSink = true
	}
}

// testWithSinkFormat is an unexported and a test option
func testWithSinkFormat(t testing.TB, fmt SinkFormat) Option {
	t.Helper()
	return func(o *options) {
		o.withSinkFormat = fmt
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

func (b *testMockBroker) Send(ctx context.Context, t eventlogger.EventType, payload any) (eventlogger.Status, error) {
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

func testLogger(t *testing.T, testLock hclog.Locker) hclog.Logger {
	t.Helper()
	return hclog.New(&hclog.LoggerOptions{
		Mutex:      testLock,
		Name:       "test",
		JSONFormat: true,
	})
}
