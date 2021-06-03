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
	"github.com/hashicorp/boundary/internal/errors"
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

func Test_NewRequestInfoContext(t *testing.T) {
	testInfo := event.TestRequestInfo(t)
	testInfoMissingId := event.TestRequestInfo(t)
	testInfoMissingId.Id = ""

	tests := []struct {
		name            string
		ctx             context.Context
		requestInfo     *event.RequestInfo
		wantErrMatch    *errors.Template
		wantErrContains string
	}{
		{
			name:            "missing-ctx",
			requestInfo:     testInfo,
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing context",
		},
		{
			name:            "missing-request-info",
			ctx:             context.Background(),
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing request info",
		},
		{
			name:            "missing-request-info-id",
			ctx:             context.Background(),
			requestInfo:     testInfoMissingId,
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing request info id",
		},
		{
			name:        "valid",
			ctx:         context.Background(),
			requestInfo: testInfo,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			ctx, err := event.NewRequestInfoContext(tt.ctx, tt.requestInfo)
			if tt.wantErrMatch != nil {
				require.Errorf(err, "should have gotten an error")
				assert.Nilf(ctx, "context should be nil")
				assert.Truef(errors.Match(tt.wantErrMatch, err), "wanted %q and got %q", tt.wantErrMatch, err)
				if tt.wantErrContains != "" {
					assert.Contains(err.Error(), tt.wantErrContains)
				}
				return
			}
			require.NoErrorf(err, "should not have been a problem getting the request info")
			require.NotNilf(ctx, "cxt returned shouldn't be nil")
			got, ok := event.RequestInfoFromContext(ctx)
			require.Truef(ok, "should be ok to get the request info")
			assert.Equal(tt.requestInfo, got)
		})
	}
}

func Test_RequestInfoFromContext(t *testing.T) {
	testInfo := event.TestRequestInfo(t)

	testCtx, err := event.NewRequestInfoContext(context.Background(), testInfo)
	require.NoError(t, err)

	tests := []struct {
		name      string
		ctx       context.Context
		wantInfo  *event.RequestInfo
		wantNotOk bool
	}{
		{
			name:      "missing-ctx",
			wantNotOk: true,
		},
		{
			name:      "no-request-info",
			ctx:       context.Background(),
			wantNotOk: true,
		},
		{
			name:     "valid",
			ctx:      testCtx,
			wantInfo: testInfo,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, ok := event.RequestInfoFromContext(tt.ctx)
			if tt.wantNotOk {
				require.Falsef(ok, "should not have returned ok for the request info")
				assert.Nilf(got, "should not have returned %q request info", got)
				return
			}
			require.Truef(ok, "should have been okay for getting the request info")
			require.NotNilf(got, "request info should not be nil")
			assert.Equal(tt.wantInfo, got)
		})
	}
}

func Test_NewEventerContext(t *testing.T) {
	testSetup := event.TestEventerConfig(t, "Test_NewEventerContext")
	testEventer, err := event.NewEventer(hclog.Default(), testSetup.EventerConfig)
	require.NoError(t, err)
	tests := []struct {
		name            string
		ctx             context.Context
		eventer         *event.Eventer
		wantErrMatch    *errors.Template
		wantErrContains string
	}{
		{
			name:            "missing-ctx",
			eventer:         testEventer,
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing context",
		},
		{
			name:            "missing-eventer",
			ctx:             context.Background(),
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing eventer",
		},
		{
			name:    "valid",
			ctx:     context.Background(),
			eventer: testEventer,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			ctx, err := event.NewEventerContext(tt.ctx, tt.eventer)
			if tt.wantErrMatch != nil {
				require.Errorf(err, "should have gotten an error")
				assert.Nilf(ctx, "context should be nil")
				assert.Truef(errors.Match(tt.wantErrMatch, err), "wanted %q and got %q", tt.wantErrMatch, err)
				if tt.wantErrContains != "" {
					assert.Contains(err.Error(), tt.wantErrContains)
				}
				return
			}
			require.NoErrorf(err, "should not have been a problem getting the eventer")
			require.NotNilf(ctx, "cxt returned shouldn't be nil")
			got, ok := event.EventerFromContext(ctx)
			require.Truef(ok, "should be ok to get the eventer")
			assert.Equal(tt.eventer, got)
		})
	}
}

func Test_EventerFromContext(t *testing.T) {
	testSetup := event.TestEventerConfig(t, "Test_EventerFromContext")

	testEventer, err := event.NewEventer(hclog.Default(), testSetup.EventerConfig)
	require.NoError(t, err)

	testEventerCtx, err := event.NewEventerContext(context.Background(), testEventer)
	require.NoError(t, err)

	tests := []struct {
		name        string
		ctx         context.Context
		wantEventer *event.Eventer
		wantNotOk   bool
	}{
		{
			name:      "missing-ctx",
			wantNotOk: true,
		},
		{
			name:      "no-eventer",
			ctx:       context.Background(),
			wantNotOk: true,
		},
		{
			name:        "valid",
			ctx:         testEventerCtx,
			wantEventer: testEventer,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, ok := event.EventerFromContext(tt.ctx)
			if tt.wantNotOk {
				require.Falsef(ok, "should not have returned ok for the eventer")
				assert.Nilf(got, "should not have returned %q eventer", got)
				return
			}
			require.Truef(ok, "should have been okay for getting an eventer")
			require.NotNilf(got, "eventer should not be nil")
			assert.Equal(tt.wantEventer, got)
		})
	}
}

func Test_WriteObservation(t *testing.T) {
	// this test and its subtests cannot be run in parallel because of it's
	// dependency on the sysEventer
	logger := hclog.New(&hclog.LoggerOptions{
		Name: "test",
	})

	c := event.TestEventerConfig(t, "WriteObservation")

	e, err := event.NewEventer(logger, c.EventerConfig)
	require.NoError(t, err)

	info := &event.RequestInfo{Id: "867-5309"}

	testCtx, err := event.NewEventerContext(context.Background(), e)
	require.NoError(t, err)
	testCtx, err = event.NewRequestInfoContext(testCtx, info)
	require.NoError(t, err)

	testCtxNoInfoId, err := event.NewEventerContext(context.Background(), e)
	require.NoError(t, err)
	noId := &event.RequestInfo{Id: "867-5309"}
	testCtxNoInfoId, err = event.NewRequestInfoContext(testCtxNoInfoId, noId)
	require.NoError(t, err)
	noId.Id = ""

	type observationPayload struct {
		header  map[string]interface{}
		details map[string]interface{}
	}

	testPayloads := []observationPayload{
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
	}

	testWantHeader := map[string]interface{}{
		"name": "bar",
		"list": []string{"1", "2"},
	}

	testWantDetails := map[string]interface{}{
		"file": "temp-file.txt",
	}

	tests := []struct {
		name                    string
		noOperation             bool
		noFlush                 bool
		observationPayload      []observationPayload
		header                  map[string]interface{}
		details                 map[string]interface{}
		ctx                     context.Context
		observationSinkFileName string
		setup                   func() error
		cleanup                 func()
		wantErrMatch            *errors.Template
		wantErrContains         string
	}{
		{
			name:    "no-info-id",
			noFlush: true,
			ctx:     testCtxNoInfoId,
			observationPayload: []observationPayload{
				{
					header: map[string]interface{}{
						"name": "bar",
					},
				},
			},
			header: map[string]interface{}{
				"name": "bar",
			},
			observationSinkFileName: c.AllEvents.Name(),
			setup: func() error {
				return event.InitSysEventer(hclog.Default(), c.EventerConfig)
			},
			cleanup: func() { event.TestResetSystEventer(t) },
		},
		{
			name:               "missing-ctx",
			observationPayload: testPayloads,
			wantErrMatch:       errors.T(errors.InvalidParameter),
			wantErrContains:    "missing context",
		},
		{
			name:               "missing-op",
			ctx:                testCtx,
			noOperation:        true,
			observationPayload: testPayloads,
			wantErrMatch:       errors.T(errors.InvalidParameter),
			wantErrContains:    "missing operation",
		},
		{
			name:    "no-header-or-details-in-payload",
			noFlush: true,
			ctx:     testCtx,
			observationPayload: []observationPayload{
				{},
			},
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "you must specify either header or details options",
		},
		{
			name:               "no-ctx-eventer-and-syseventer-not-initialized",
			ctx:                context.Background(),
			observationPayload: testPayloads,
			wantErrMatch:       errors.T(errors.InvalidParameter),
			wantErrContains:    "missing both context and system eventer",
		},
		{
			name:    "use-syseventer",
			noFlush: true,
			ctx:     context.Background(),
			observationPayload: []observationPayload{
				{
					header: map[string]interface{}{
						"name": "bar",
					},
				},
			},
			header: map[string]interface{}{
				"name": "bar",
			},
			observationSinkFileName: c.AllEvents.Name(),
			setup: func() error {
				return event.InitSysEventer(hclog.Default(), c.EventerConfig)
			},
			cleanup: func() { event.TestResetSystEventer(t) },
		},
		{
			name:                    "simple",
			ctx:                     testCtx,
			observationPayload:      testPayloads,
			header:                  testWantHeader,
			details:                 testWantDetails,
			observationSinkFileName: c.AllEvents.Name(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			if tt.setup != nil {
				require.NoError(tt.setup())
			}
			if tt.cleanup != nil {
				defer tt.cleanup()
			}
			op := tt.name
			if tt.noOperation {
				op = ""
			}
			require.Greater(len(tt.observationPayload), 0)
			for _, p := range tt.observationPayload {
				err := event.WriteObservation(tt.ctx, event.Op(op), event.WithHeader(p.header), event.WithDetails(p.details))
				if tt.wantErrMatch != nil {
					require.Errorf(err, "wanted error %q", tt.wantErrMatch)
					if tt.wantErrContains != "" {
						assert.Contains(err.Error(), tt.wantErrContains)
					}
					return
				}
				require.NoError(err)
			}
			if !tt.noFlush {
				require.NoError(event.WriteObservation(tt.ctx, event.Op(tt.name), event.WithFlush()))
			}

			if tt.observationSinkFileName != "" {
				defer func() { _ = os.WriteFile(tt.observationSinkFileName, nil, 0o666) }()
				b, err := ioutil.ReadFile(tt.observationSinkFileName)
				assert.NoError(err)

				gotObservation := &eventJson{}
				err = json.Unmarshal(b, gotObservation)
				require.NoErrorf(err, "json: %s", string(b))

				actualJson, err := json.Marshal(gotObservation)
				require.NoError(err)
				wantJson := testObservationJsonFromCtx(t, tt.ctx, event.Op(tt.name), gotObservation, tt.header, tt.details)

				assert.JSONEq(string(wantJson), string(actualJson))
			}
		})
	}
}

func testObservationJsonFromCtx(t *testing.T, ctx context.Context, caller event.Op, got *eventJson, hdr, details map[string]interface{}) []byte {
	t.Helper()
	require := require.New(t)

	reqInfo, _ := event.RequestInfoFromContext(ctx)
	// require.Truef(ok, "missing reqInfo in ctx")

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
	// this test and its subtests cannot be run in parallel because of it's
	// dependency on the sysEventer
	now := time.Now()

	logger := hclog.New(&hclog.LoggerOptions{
		Name: "test",
	})

	c := event.TestEventerConfig(t, "WriteAudit")

	e, err := event.NewEventer(logger, c.EventerConfig, event.WithNow(now))
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
		auditSinkFileName string
		setup             func() error
		cleanup           func()
		noOperation       bool
		noFlush           bool
		wantErrMatch      *errors.Template
		wantErrContains   string
	}{
		{
			name: "missing-ctx",
			auditOpts: [][]event.Option{
				{
					event.WithAuth(testAuth),
					event.WithRequest(testReq),
				},
			},
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing context",
		},
		{
			name: "missing-op",
			ctx:  ctx,
			auditOpts: [][]event.Option{
				{
					event.WithAuth(testAuth),
					event.WithRequest(testReq),
				},
			},
			noOperation:     true,
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing operation",
		},
		{
			name: "no-ctx-eventer-and-syseventer-not-initialized",
			ctx:  context.Background(),
			auditOpts: [][]event.Option{
				{
					event.WithAuth(testAuth),
					event.WithRequest(testReq),
				},
			},
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing both context and system eventer",
		},
		{
			name:    "use-syseventer",
			noFlush: true,
			ctx:     context.Background(),
			auditOpts: [][]event.Option{
				{
					event.WithAuth(testAuth),
					event.WithRequest(testReq),
				},
			},
			wantAudit: &event.Audit{
				Auth:    testAuth,
				Request: testReq,
			},
			setup: func() error {
				return event.InitSysEventer(hclog.Default(), c.EventerConfig)
			},
			cleanup:           func() { event.TestResetSystEventer(t) },
			auditSinkFileName: c.AllEvents.Name(),
		},
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
			auditSinkFileName: c.AllEvents.Name(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			if tt.setup != nil {
				require.NoError(tt.setup())
			}
			if tt.cleanup != nil {
				defer tt.cleanup()
			}
			op := tt.name
			if tt.noOperation {
				op = ""
			}
			require.Greater(len(tt.auditOpts), 0)
			for _, opts := range tt.auditOpts {
				opts := append(opts, event.WithNow(now))
				err := event.WriteAudit(tt.ctx, event.Op(op), opts...)
				if tt.wantErrMatch != nil {
					require.Errorf(err, "wanted error %q", tt.wantErrMatch)
					if tt.wantErrContains != "" {
						assert.Contains(err.Error(), tt.wantErrContains)
					}
					return
				}
				require.NoError(err)
			}
			if !tt.noFlush {
				require.NoError(event.WriteAudit(tt.ctx, event.Op(op), event.WithFlush(), event.WithNow(now)))
			}
			if tt.auditSinkFileName != "" {
				defer func() { _ = os.WriteFile(tt.auditSinkFileName, nil, 0o666) }()

				b, err := ioutil.ReadFile(tt.auditSinkFileName)
				require.NoError(err)
				gotAudit := &eventJson{}
				err = json.Unmarshal(b, gotAudit)
				require.NoErrorf(err, "json: %s", string(b))

				actualJson, err := json.Marshal(gotAudit)
				require.NoError(err)

				wantEvent := eventJson{
					CreatedAt: gotAudit.CreatedAt,
					EventType: string(gotAudit.EventType),
					Payload: map[string]interface{}{
						"auth":            tt.wantAudit.Auth,
						"id":              gotAudit.Payload["id"],
						"timestamp":       now,
						"request":         tt.wantAudit.Request,
						"serialized_hmac": "",
						"type":            event.ApiRequest,
						"version":         event.AuditVersion,
					},
				}
				if tt.wantAudit.Id != "" {
					wantEvent.Payload["id"] = tt.wantAudit.Id
					wantEvent.Payload["request_info"] = event.RequestInfo{
						Id: tt.wantAudit.Id,
					}
				}
				if tt.wantAudit.Response != nil {
					wantEvent.Payload["response"] = tt.wantAudit.Response
				}
				wantJson, err := json.Marshal(wantEvent)
				require.NoError(err)

				assert.JSONEq(string(wantJson), string(actualJson))
			}
		})
	}
}

func Test_WriteError(t *testing.T) {
	// this test and its subtests cannot be run in parallel because of it's
	// dependency on the sysEventer
	now := time.Now()

	logger := hclog.New(&hclog.LoggerOptions{
		Name: "test",
	})

	c := event.TestEventerConfig(t, "WriteAudit")

	e, err := event.NewEventer(logger, c.EventerConfig, event.WithNow(now))
	require.NoError(t, err)

	info := &event.RequestInfo{Id: "867-5309"}

	testCtx, err := event.NewEventerContext(context.Background(), e)
	require.NoError(t, err)
	testCtx, err = event.NewRequestInfoContext(testCtx, info)
	require.NoError(t, err)

	testCtxNoInfoId, err := event.NewEventerContext(context.Background(), e)
	require.NoError(t, err)
	noId := &event.RequestInfo{Id: "867-5309"}
	testCtxNoInfoId, err = event.NewRequestInfoContext(testCtxNoInfoId, noId)
	require.NoError(t, err)
	noId.Id = ""

	testError := errors.New(errors.InvalidParameter, "test", "you lookin at me?")

	tests := []struct {
		name            string
		ctx             context.Context
		e               error
		info            *event.RequestInfo
		setup           func() error
		cleanup         func()
		noOperation     bool
		errSinkFileName string
		noOutput        bool
	}{
		{
			name:        "missing-caller",
			ctx:         testCtx,
			e:           testError,
			noOperation: true,
			noOutput:    true,
		},
		{
			name:            "no-ctx-eventer-and-syseventer-not-initialized",
			ctx:             context.Background(),
			e:               testError,
			errSinkFileName: c.ErrorEvents.Name(),
			noOutput:        true,
		},
		{
			name: "use-syseventer",
			ctx:  context.Background(),
			e:    testError,
			setup: func() error {
				return event.InitSysEventer(hclog.Default(), c.EventerConfig)
			},
			cleanup:         func() { event.TestResetSystEventer(t) },
			errSinkFileName: c.ErrorEvents.Name(),
		},
		{
			name: "no-info-id",
			ctx:  testCtxNoInfoId,
			e:    testError,
			info: &event.RequestInfo{},
			setup: func() error {
				return event.InitSysEventer(hclog.Default(), c.EventerConfig)
			},
			cleanup:         func() { event.TestResetSystEventer(t) },
			errSinkFileName: c.ErrorEvents.Name(),
		},
		{
			name:            "simple",
			ctx:             testCtx,
			e:               testError,
			info:            info,
			errSinkFileName: c.ErrorEvents.Name(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			if tt.setup != nil {
				require.NoError(tt.setup())
			}
			if tt.cleanup != nil {
				defer tt.cleanup()
			}
			op := tt.name
			if tt.noOperation {
				op = ""
			}
			event.WriteError(tt.ctx, event.Op(op), tt.e)
			if tt.errSinkFileName != "" {
				defer func() { _ = os.WriteFile(tt.errSinkFileName, nil, 0666) }()
				b, err := ioutil.ReadFile(tt.errSinkFileName)
				require.NoError(err)

				if tt.noOutput {
					assert.Lenf(b, 0, "should be an empty file: %s", string(b))
					return
				}

				gotError := &eventJson{}
				err = json.Unmarshal(b, gotError)
				require.NoErrorf(err, "json: %s", string(b))

				actualJson, err := json.Marshal(gotError)
				require.NoError(err)

				wantError := eventJson{
					CreatedAt: gotError.CreatedAt,
					EventType: string(gotError.EventType),
					Payload: map[string]interface{}{
						"error": map[string]interface{}{
							"Code":    tt.e.(*errors.Err).Code,
							"Msg":     tt.e.(*errors.Err).Msg,
							"Op":      tt.e.(*errors.Err).Op,
							"Wrapped": tt.e.(*errors.Err).Wrapped,
						},
						"id":      gotError.Payload["id"],
						"op":      op,
						"version": event.ErrorVersion,
					},
				}
				if tt.info != nil && tt.info.Id != "" {
					wantError.Payload["id"] = tt.info.Id
				}
				if tt.info != nil {
					wantError.Payload["request_info"] = tt.info

				}
				wantJson, err := json.Marshal(wantError)
				require.NoError(err)

				assert.JSONEq(string(wantJson), string(actualJson))
			}
		})
	}
}
