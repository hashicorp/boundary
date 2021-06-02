package event

import (
	"io/ioutil"
	"os"
	"sync"
	"testing"

	"github.com/hashicorp/boundary/internal/gen/controller/api/resources/groups"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var testSysEventerLock sync.Mutex

func testResetSystEventer(t *testing.T) {
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

func TestEventerConfig(t *testing.T, testName string) TestConfig {
	t.Helper()
	require := require.New(t)
	tmpAllFile, err := ioutil.TempFile("./", "tmp-observations-"+testName)
	require.NoError(err)

	tmpErrFile, err := ioutil.TempFile("./", "tmp-errors-"+testName)
	require.NoError(err)

	return TestConfig{
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
}

func testRequestInfo(t *testing.T) *RequestInfo {
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
