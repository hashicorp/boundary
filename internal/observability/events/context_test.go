package event_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/golang/protobuf/ptypes/wrappers"
	pb "github.com/hashicorp/boundary/internal/gen/controller/api/resources/hosts"
	"github.com/hashicorp/boundary/internal/gen/controller/api/resources/scopes"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/host/static"
	event "github.com/hashicorp/boundary/internal/observability/events"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

func Test_WriteObservation(t *testing.T) {

	logger := hclog.New(&hclog.LoggerOptions{
		Name: "test",
	})

	tmpFile, err := ioutil.TempFile("./", "test_writeobservation-observation")
	require.NoError(t, err)
	tmpFile.Close()
	defer os.Remove(tmpFile.Name()) // just to be sure it's gone after all the tests are done.

	tmpErrFile, err := ioutil.TempFile("./", "test_writeobservation-err")
	require.NoError(t, err)
	tmpErrFile.Close()
	defer os.Remove(tmpErrFile.Name()) // just to be sure it's gone after all the tests are done.

	c := event.EventerConfig{
		ObservationsEnabled: true,
		ObservationDelivery: event.Enforced,
		Sinks: []event.SinkConfig{
			{
				Name:       "observation-file-sink",
				EventTypes: []event.Type{event.EveryType},
				Format:     event.JSONSinkFormat,
				Path:       "./",
				FileName:   tmpFile.Name(),
			},
			{
				Name:       "stdout",
				EventTypes: []event.Type{event.EveryType},
				Format:     event.JSONSinkFormat,
				SinkType:   event.StdoutSink,
			},
			{
				Name:       "err-file-sink",
				EventTypes: []event.Type{event.ErrorType},
				Format:     event.JSONSinkFormat,
				Path:       "./",
				FileName:   tmpErrFile.Name(),
			},
		},
	}
	e, err := event.NewEventer(logger, c)
	require.NoError(t, err)

	info := &event.RequestInfo{Id: "867-5309"}

	ctx, err := event.NewEventerContext(context.Background(), e)
	require.NoError(t, err)
	ctx, err = event.NewRequestInfoContext(ctx, info)
	require.NoError(t, err)
	type observationPayload struct {
		header  map[string]interface{}
		details map[string]interface{}
	}
	tests := []struct {
		name                    string
		observationPayload      []observationPayload
		header                  map[string]interface{}
		details                 map[string]interface{}
		ctx                     context.Context
		errSinkFileName         string
		observationSinkFileName string
	}{
		{
			name: "simple",
			ctx:  ctx,
			observationPayload: []observationPayload{
				{
					header: map[string]interface{}{
						"name": "bar",
					},
				},
				{
					header: map[string]interface{}{
						"list": []string{"1", "2"},
					},
				},
				{
					details: map[string]interface{}{
						"file": "temp-file.txt",
					},
				},
			},
			header: map[string]interface{}{
				"name": "bar",
				"list": []string{"1", "2"},
			},
			details: map[string]interface{}{
				"file": "temp-file.txt",
			},
			errSinkFileName:         tmpErrFile.Name(),
			observationSinkFileName: tmpFile.Name(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			for _, p := range tt.observationPayload {
				err := event.WriteObservation(tt.ctx, event.Op(tt.name), event.WithHeader(p.header), event.WithDetails(p.details))
				require.NoError(err)
			}
			require.NoError(event.WriteObservation(tt.ctx, event.Op(tt.name), event.WithFlush()))

			if tt.observationSinkFileName != "" {
				defer os.Remove(tt.observationSinkFileName)
				b, err := ioutil.ReadFile(tt.observationSinkFileName)
				require.NoError(err)
				gotObservation := &eventJson{}
				err = json.Unmarshal(b, gotObservation)
				require.NoError(err)

				actualJson, err := json.Marshal(gotObservation)
				require.NoError(err)
				wantJson := testObservationJsonFromCtx(t, tt.ctx, event.Op(tt.name), gotObservation, tt.header, tt.details)

				assert.JSONEq(string(wantJson), string(actualJson))
			}

			if tt.errSinkFileName != "" {
				defer os.Remove(tt.errSinkFileName)
				b, err := ioutil.ReadFile(tt.errSinkFileName)
				require.NoError(err)
				assert.Equal(0, len(b))
			}
		})
	}

}

func testObservationJsonFromCtx(t *testing.T, ctx context.Context, caller event.Op, got *eventJson, hdr, details map[string]interface{}) []byte {
	t.Helper()
	require := require.New(t)

	reqInfo, ok := event.RequestInfoFromContext(ctx)
	require.Truef(ok, "missing reqInfo in ctx")

	j := eventJson{
		CreatedAt: got.CreatedAt,
		EventType: string(event.ObservationType),
		Payload: map[string]interface{}{
			event.IdField: got.Payload[event.IdField].(string),
			event.HeaderField: map[string]interface{}{
				event.RequestInfoField: reqInfo,
				event.VersionField:     event.ObservationVersion,
			},
		},
	}
	if hdr != nil {
		h := j.Payload[event.HeaderField].(map[string]interface{})
		for k, v := range hdr {
			h[k] = v
		}
	}
	if details != nil {
		details[event.OpField] = string(caller)
		d := got.Payload[event.DetailsField].([]interface{})[0].(map[string]interface{})
		j.Payload[event.DetailsField] = []struct {
			CreatedAt string                 `json:"created_at"`
			Type      string                 `json:"type"`
			Payload   map[string]interface{} `json:"payload"`
		}{
			{
				CreatedAt: d[event.CreatedAtField].(string),
				Type:      d[event.TypeField].(string),
				Payload:   details,
			},
		}
	}
	b, err := json.Marshal(j)
	require.NoError(err)
	return b
}

type eventJson struct {
	CreatedAt string                 `json:"created_at"`
	EventType string                 `json:"event_type"`
	Payload   map[string]interface{} `json:"payload"`
}

func Test_WriteAudit(t *testing.T) {

	now := time.Now()

	logger := hclog.New(&hclog.LoggerOptions{
		Name: "test",
	})

	tmpFile, err := ioutil.TempFile("./", "test_writeaudit-audit")
	require.NoError(t, err)
	tmpFile.Close()
	defer os.Remove(tmpFile.Name()) // just to be sure it's gone after all the tests are done.

	tmpErrFile, err := ioutil.TempFile("./", "test_writeaudit-err")
	require.NoError(t, err)
	tmpErrFile.Close()
	defer os.Remove(tmpErrFile.Name()) // just to be sure it's gone after all the tests are done.

	c := event.EventerConfig{
		AuditEnabled:  true,
		AuditDelivery: event.Enforced,
		Sinks: []event.SinkConfig{
			{
				Name:       "audit-file-sink",
				EventTypes: []event.Type{event.EveryType},
				Format:     event.JSONSinkFormat,
				Path:       "./",
				FileName:   tmpFile.Name(),
			},
			{
				Name:       "stdout",
				EventTypes: []event.Type{event.EveryType},
				Format:     event.JSONSinkFormat,
				SinkType:   event.StdoutSink,
			},
			{
				Name:       "err-file-sink",
				EventTypes: []event.Type{event.ErrorType},
				Format:     event.JSONSinkFormat,
				Path:       "./",
				FileName:   tmpErrFile.Name(),
			},
		},
	}
	e, err := event.NewEventer(logger, c, event.WithNow(now))
	require.NoError(t, err)

	info := &event.RequestInfo{Id: "867-5309"}

	ctx, err := event.NewEventerContext(context.Background(), e)
	require.NoError(t, err)
	ctx, err = event.NewRequestInfoContext(ctx, info)
	require.NoError(t, err)

	testAuth := &event.Auth{}
	testReq := &event.Request{
		Operation: "POST",
		Endpoint:  "/v1/hosts",
		Details: &pbs.CreateHostRequest{Item: &pb.Host{
			HostCatalogId: "hc_1234567890",
			Name:          &wrappers.StringValue{Value: "name"},
			Description:   &wrappers.StringValue{Value: "desc"},
			Type:          "static",
			Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
				"address": structpb.NewStringValue("123.456.789"),
			}},
		}},
	}
	testAuthorizedActions := []string{"no-op", "read", "update", "delete"}

	testResp := &event.Response{
		StatusCode: 200,
		Details: &pbs.CreateHostResponse{
			Uri: fmt.Sprintf("hosts/%s_", static.HostPrefix),
			Item: &pb.Host{
				HostCatalogId: "hc_1234567890",
				Scope:         &scopes.ScopeInfo{Id: "proj_1234567890", Type: scope.Project.String(), ParentScopeId: "org_1234567890"},
				Name:          &wrappers.StringValue{Value: "name"},
				Description:   &wrappers.StringValue{Value: "desc"},
				Type:          "static",
				Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
					"address": structpb.NewStringValue("123.456.789"),
				}},
				AuthorizedActions: testAuthorizedActions,
			},
		},
	}
	tests := []struct {
		name              string
		auditOpts         [][]event.Option
		wantAudit         *event.Audit
		ctx               context.Context
		errSinkFileName   string
		auditSinkFileName string
	}{
		{
			name: "simple",
			ctx:  ctx,
			auditOpts: [][]event.Option{
				{
					event.WithAuth(testAuth),
					event.WithRequest(testReq),
				},
				{
					event.WithResponse(testResp),
				},
			},
			wantAudit: &event.Audit{
				Id:       "867-5309",
				Auth:     testAuth,
				Request:  testReq,
				Response: testResp,
			},
			errSinkFileName:   tmpErrFile.Name(),
			auditSinkFileName: tmpFile.Name(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			for _, opts := range tt.auditOpts {
				opts := append(opts, event.WithNow(now))
				err := event.WriteAudit(tt.ctx, event.Op(tt.name), opts...)
				require.NoError(err)
			}
			require.NoError(event.WriteAudit(tt.ctx, event.Op(tt.name), event.WithFlush(), event.WithNow(now)))

			if tt.auditSinkFileName != "" {
				defer os.Remove(tt.auditSinkFileName)
				b, err := ioutil.ReadFile(tt.auditSinkFileName)
				require.NoError(err)
				gotAudit := &eventJson{}
				err = json.Unmarshal(b, gotAudit)
				require.NoError(err)

				actualJson, err := json.Marshal(gotAudit)
				require.NoError(err)

				wantEvent := eventJson{
					CreatedAt: gotAudit.CreatedAt,
					EventType: string(gotAudit.EventType),
					Payload: map[string]interface{}{
						"auth":            tt.wantAudit.Auth,
						"id":              tt.wantAudit.Id,
						"timestamp":       now,
						"request":         tt.wantAudit.Request,
						"response":        tt.wantAudit.Response,
						"serialized_hmac": "",
						"type":            event.ApiRequest,
						"version":         event.AuditVersion,
						"request_info": event.RequestInfo{
							Id: tt.wantAudit.Id,
						},
					},
				}
				wantJson, err := json.Marshal(wantEvent)
				require.NoError(err)

				assert.JSONEq(string(wantJson), string(actualJson))
			}

			if tt.errSinkFileName != "" {
				defer os.Remove(tt.errSinkFileName)
				b, err := ioutil.ReadFile(tt.errSinkFileName)
				require.NoError(err)
				assert.Equal(0, len(b))
			}
		})
	}

}
