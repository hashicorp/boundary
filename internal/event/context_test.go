// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package event_test

import (
	"context"
	"encoding/json"
	stderrors "errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/event"
	pbs "github.com/hashicorp/boundary/internal/gen/testing/event"
	"github.com/hashicorp/eventlogger/filters/encrypt"
	"github.com/hashicorp/eventlogger/formatter_filters/cloudevents"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-uuid"
	"github.com/mitchellh/copystructure"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

const apiRequest = "APIRequest"

const (
	testAuditVersion       = "v0.1"
	testObservationVersion = "v0.1"
)

type testAudit struct {
	Id            string             `json:"id"`                     // std audit/boundary field
	Version       string             `json:"version"`                // std audit/boundary field
	Type          string             `json:"type"`                   // std audit field
	Timestamp     time.Time          `json:"timestamp"`              // std audit field
	RequestInfo   *event.RequestInfo `json:"request_info,omitempty"` // boundary field
	Auth          *event.Auth        `json:"auth,omitempty"`         // std audit field
	Request       *event.Request     `json:"request,omitempty"`      // std audit field
	Response      *event.Response    `json:"response,omitempty"`     // std audit field
	Flush         bool               `json:"-"`
	CorrelationId string             `json:"correlation_id,omitempty"`
}

func Test_NewRequestInfoContext(t *testing.T) {
	testInfo := event.TestRequestInfo(t)
	testInfoMissingId := event.TestRequestInfo(t)
	testInfoMissingId.Id = ""

	testInfoMissingEventId := event.TestRequestInfo(t)
	testInfoMissingEventId.EventId = ""

	tests := []struct {
		name            string
		ctx             context.Context
		requestInfo     *event.RequestInfo
		wantErrIs       error
		wantErrContains string
	}{
		{
			name:            "missing-ctx",
			requestInfo:     testInfo,
			wantErrIs:       event.ErrInvalidParameter,
			wantErrContains: "missing context",
		},
		{
			name:            "missing-request-info",
			ctx:             context.Background(),
			wantErrIs:       event.ErrInvalidParameter,
			wantErrContains: "missing request info",
		},
		{
			name:            "missing-request-info-id",
			ctx:             context.Background(),
			requestInfo:     testInfoMissingId,
			wantErrIs:       event.ErrInvalidParameter,
			wantErrContains: "missing request info id",
		},
		{
			name:            "missing-request-info-event-id",
			ctx:             context.Background(),
			requestInfo:     testInfoMissingEventId,
			wantErrIs:       event.ErrInvalidParameter,
			wantErrContains: "missing request info event id",
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
			if tt.wantErrIs != nil {
				require.Errorf(err, "should have gotten an error")
				assert.Nilf(ctx, "context should be nil")
				assert.ErrorIs(err, tt.wantErrIs)
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
	testLock := &sync.Mutex{}
	testLogger := testLogger(t, testLock)
	testEventer, err := event.NewEventer(testLogger, testLock, "Test_NewEventerContext", testSetup.EventerConfig)
	require.NoError(t, err)
	tests := []struct {
		name            string
		ctx             context.Context
		eventer         *event.Eventer
		wantErrIs       error
		wantErrContains string
	}{
		{
			name:            "missing-ctx",
			eventer:         testEventer,
			wantErrIs:       event.ErrInvalidParameter,
			wantErrContains: "missing context",
		},
		{
			name:            "missing-eventer",
			ctx:             context.Background(),
			wantErrIs:       event.ErrInvalidParameter,
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
			if tt.wantErrIs != nil {
				require.Errorf(err, "should have gotten an error")
				assert.Nilf(ctx, "context should be nil")
				assert.ErrorIs(err, tt.wantErrIs)
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

	testLock := &sync.Mutex{}
	testLogger := testLogger(t, testLock)
	testEventer, err := event.NewEventer(testLogger, testLock, "Test_EventerFromContext", testSetup.EventerConfig)
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

	c := event.TestEventerConfig(t, "WriteObservation")

	testLock := &sync.Mutex{}
	testLogger := testLogger(t, testLock)
	e, err := event.NewEventer(testLogger, testLock, "Test_WriteObservation", c.EventerConfig)
	require.NoError(t, err)

	info := &event.RequestInfo{Id: "867-5309", EventId: "411"}

	testCtx, err := event.NewEventerContext(context.Background(), e)
	require.NoError(t, err)
	testCtx, err = event.NewRequestInfoContext(testCtx, info)
	require.NoError(t, err)

	testCtxNoEventInfoId, err := event.NewEventerContext(context.Background(), e)
	require.NoError(t, err)
	noEventId := &event.RequestInfo{Id: "867-5309", EventId: "411"}
	testCtxNoEventInfoId, err = event.NewRequestInfoContext(testCtxNoEventInfoId, noEventId)
	require.NoError(t, err)
	noEventId.EventId = ""
	noEventId.Id = ""

	type observationPayload struct {
		header  []any
		details []any
	}

	testPayloads := []observationPayload{
		{
			header: []any{"name", "bar"},
		},
		{
			header: []any{"list", []string{"1", "2"}},
		},
		{
			details: []any{"file", "temp-file.txt"},
		},
	}

	testWantHeader := map[string]any{
		"name": "bar",
		"list": []string{"1", "2"},
	}

	testWantDetails := map[string]any{
		"file": "temp-file.txt",
	}

	tests := []struct {
		name                    string
		noOperation             bool
		noFlush                 bool
		telemetryFlag           bool
		observationPayload      []observationPayload
		header                  map[string]any
		details                 map[string]any
		Request                 *event.Request
		Response                *event.Response
		ctx                     context.Context
		observationSinkFileName string
		setup                   func() error
		cleanup                 func()
		wantErrIs               error
		wantErrContains         string
	}{
		{
			name:          "no-info-event-id",
			noFlush:       true,
			telemetryFlag: true,
			ctx:           testCtxNoEventInfoId,
			observationPayload: []observationPayload{
				{
					header: []any{"name", "bar"},
				},
			},
			header: map[string]any{
				"name": "bar",
			},
			observationSinkFileName: c.AllEvents.Name(),
			setup: func() error {
				return event.InitSysEventer(testLogger, testLock, "no-info-event-id", event.WithEventerConfig(&c.EventerConfig))
			},
			cleanup: func() { event.TestResetSystEventer(t) },
		},
		{
			name:               "missing-ctx",
			observationPayload: testPayloads,
			wantErrIs:          event.ErrInvalidParameter,
			wantErrContains:    "missing context",
		},
		{
			name:               "missing-op",
			ctx:                testCtx,
			noOperation:        true,
			observationPayload: testPayloads,
			wantErrIs:          event.ErrInvalidParameter,
			wantErrContains:    "missing operation",
		},
		{
			name:    "no-header-or-details-in-payload",
			noFlush: true,
			ctx:     testCtx,
			observationPayload: []observationPayload{
				{},
			},
			wantErrIs:       event.ErrInvalidParameter,
			wantErrContains: "specify either header or details options",
		},
		{
			name:    "no-header-or-details-in-payload-no-request-no-response",
			ctx:     testCtx,
			noFlush: true,
			observationPayload: []observationPayload{
				{},
			},
			wantErrIs:       event.ErrInvalidParameter,
			wantErrContains: "specify either header or details options or request or response for an event payload",
		},
		{
			name:          "telemetry-not-enabled-but-request-or-response-available",
			ctx:           testCtx,
			noFlush:       true,
			telemetryFlag: false,
			Request: &event.Request{
				Operation: "create-test",
				Endpoint:  "0.0.0.0",
			},
			observationPayload: testPayloads,
		},
		{
			name:               "no-ctx-eventer-and-syseventer-not-initialized",
			ctx:                context.Background(),
			observationPayload: testPayloads,
			wantErrIs:          event.ErrInvalidParameter,
			wantErrContains:    "missing both context and system eventer",
		},
		{
			name:          "use-syseventer",
			noFlush:       true,
			telemetryFlag: true,
			ctx:           context.Background(),
			observationPayload: []observationPayload{
				{
					header: []any{"name", "bar"},
				},
			},
			header: map[string]any{
				"name": "bar",
			},
			observationSinkFileName: c.AllEvents.Name(),
			setup: func() error {
				return event.InitSysEventer(testLogger, testLock, "use-syseventer", event.WithEventerConfig(&c.EventerConfig))
			},
			cleanup: func() { event.TestResetSystEventer(t) },
		},
		{
			name:          "use-syseventer-with-cancelled-ctx",
			noFlush:       true,
			telemetryFlag: true,
			ctx: func() context.Context {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				return ctx
			}(),
			observationPayload: []observationPayload{
				{
					header: []any{"name", "bar"},
				},
			},
			header: map[string]any{
				"name": "bar",
			},
			observationSinkFileName: c.AllEvents.Name(),
			setup: func() error {
				return event.InitSysEventer(testLogger, testLock, "use-syseventer", event.WithEventerConfig(&c.EventerConfig))
			},
			cleanup: func() { event.TestResetSystEventer(t) },
		},
		{
			name:               "simple-header",
			ctx:                testCtx,
			telemetryFlag:      true,
			observationPayload: testPayloads,
			header:             testWantHeader,
		},
		{
			name:               "simple-details",
			ctx:                testCtx,
			telemetryFlag:      true,
			observationPayload: testPayloads,
			details:            testWantDetails,
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
				err := event.WriteObservation(tt.ctx, event.Op(op), event.WithHeader(p.header...), event.WithDetails(p.details...),
					event.WithRequest(tt.Request),
					event.WithResponse(tt.Response))
				if tt.wantErrIs != nil {
					assert.ErrorIs(err, tt.wantErrIs)
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

			if !tt.telemetryFlag {
				require.Nil(event.WriteObservation(tt.ctx, event.Op(tt.name), event.WithRequest(tt.Request),
					event.WithResponse(tt.Response)))
				require.Nil(event.WriteObservation(tt.ctx, event.Op(tt.name), event.WithDetails(tt.details)))
			}
			if tt.observationSinkFileName != "" {
				defer func() { _ = os.WriteFile(tt.observationSinkFileName, nil, 0o666) }()
				b, err := os.ReadFile(tt.observationSinkFileName)
				assert.NoError(err)

				gotObservation := &cloudevents.Event{}
				err = json.Unmarshal(b, gotObservation)
				require.NoErrorf(err, "json: %s", string(b))

				actualJson, err := json.Marshal(gotObservation)
				require.NoError(err)
				wantJson := testObservationJsonFromCtx(t, tt.ctx, event.Op(tt.name), gotObservation, tt.header, tt.details)

				assert.JSONEq(string(wantJson), string(actualJson))
			}
		})
	}
	t.Run("not-enabled", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)

		c := event.TestEventerConfig(t, "WriteObservation")
		c.EventerConfig.ObservationsEnabled = false
		testLock := &sync.Mutex{}
		e, err := event.NewEventer(testLogger, testLock, "not-enabled", c.EventerConfig)
		require.NoError(err)

		testCtx, err := event.NewEventerContext(context.Background(), e)
		require.NoError(err)
		testCtx, err = event.NewRequestInfoContext(testCtx, info)
		require.NoError(err)

		hdr := map[string]any{
			"list": []string{"1", "2"},
		}
		require.NoError(event.WriteObservation(testCtx, "not-enabled", event.WithHeader(hdr), event.WithFlush()))

		b, err := os.ReadFile(c.AllEvents.Name())
		assert.NoError(err)
		assert.Len(b, 0)
	})
}

func Test_Filtering(t *testing.T) {
	testLock := &sync.Mutex{}
	testLogger := testLogger(t, testLock)
	tests := []struct {
		name  string
		allow []string
		deny  []string
		hdr   []any
		found bool
	}{
		{
			name:  "allowed",
			allow: []string{`"/data/list" contains "1"`},
			hdr:   []any{"list", []string{"1", "2"}},
			found: true,
		},
		{
			name:  "not-allowed",
			allow: []string{`"/data/list" contains "22"`},
			hdr:   []any{"list", []string{"1", "2"}},
			found: false,
		},
		{
			name:  "deny",
			deny:  []string{`"/data/list" contains "1"`},
			hdr:   []any{"list", []string{"1", "2"}},
			found: false,
		},
		{
			name:  "not-deny",
			deny:  []string{`"/data/list" contains "22"`},
			hdr:   []any{"list", []string{"1", "2"}},
			found: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			info := &event.RequestInfo{Id: "867-5309", EventId: "411"}

			c := event.TestEventerConfig(t, "WriteObservation-filtering")
			c.EventerConfig.Sinks[0].AllowFilters = tt.allow
			c.EventerConfig.Sinks[0].DenyFilters = tt.deny

			e, err := event.NewEventer(testLogger, testLock, "filtering", c.EventerConfig)
			require.NoError(err)

			testCtx, err := event.NewEventerContext(context.Background(), e)
			require.NoError(err)
			testCtx, err = event.NewRequestInfoContext(testCtx, info)
			require.NoError(err)

			require.NoError(event.WriteObservation(testCtx, "not-enabled", event.WithHeader(tt.hdr...), event.WithFlush()))

			b, err := os.ReadFile(c.AllEvents.Name())
			assert.NoError(err)
			switch tt.found {
			case true:
				assert.NotEmpty(b)
			case false:
				assert.Empty(b)
			}
		})
	}
}

func Test_DefaultEventerConfig(t *testing.T) {
	t.Run("assert-default", func(t *testing.T) {
		assert.Equal(t, &event.EventerConfig{
			AuditEnabled:        false,
			ObservationsEnabled: true,
			SysEventsEnabled:    true,
			Sinks:               []*event.SinkConfig{event.DefaultSink()},
		}, event.DefaultEventerConfig())
	})
}

func testObservationJsonFromCtx(t *testing.T, ctx context.Context, caller event.Op, got *cloudevents.Event, hdr, details map[string]any) []byte {
	t.Helper()
	require := require.New(t)

	reqInfo, _ := event.RequestInfoFromContext(ctx)
	// require.Truef(ok, "missing reqInfo in ctx")

	j := cloudevents.Event{
		ID:              got.ID,
		Time:            got.Time,
		Source:          got.Source,
		SpecVersion:     got.SpecVersion,
		Type:            got.Type,
		DataContentType: got.DataContentType,
		Data: map[string]any{
			event.RequestInfoField: reqInfo,
			event.VersionField:     testObservationVersion,
		},
	}
	if hdr != nil {
		h := j.Data.(map[string]any)
		for k, v := range hdr {
			h[k] = v
		}
	}
	if details != nil {
		details[event.OpField] = string(caller)
		d := got.Data.(map[string]any)[event.DetailsField].([]any)[0].(map[string]any)
		j.Data.(map[string]any)[event.DetailsField] = []struct {
			CreatedAt string         `json:"created_at"`
			Type      string         `json:"type"`
			Payload   map[string]any `json:"payload"`
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

func Test_WriteAudit(t *testing.T) {
	// this test and its subtests cannot be run in parallel because of it's
	// dependency on the sysEventer
	now := time.Now()

	c := event.TestEventerConfig(t, "WriteAudit")
	testLock := &sync.Mutex{}
	testLogger := testLogger(t, testLock)
	e, err := event.NewEventer(testLogger, testLock, "Test_WriteAudit", c.EventerConfig)
	require.NoError(t, err)

	info := &event.RequestInfo{Id: "867-5309", EventId: "411"}

	ctx, err := event.NewEventerContext(context.Background(), e)
	require.NoError(t, err)
	ctx, err = event.NewRequestInfoContext(ctx, info)
	require.NoError(t, err)
	corId, err := uuid.GenerateUUID()
	require.NoError(t, err)
	ctx, err = event.NewCorrelationIdContext(ctx, corId)
	require.NoError(t, err)

	testAuth := &event.Auth{
		AuthTokenId: "test_auth_token_id",
		UserEmail:   "test_user_email",
		UserName:    "test_user_name",
		UserInfo: &event.UserInfo{
			UserId:        "test_user_id",
			AuthAccountId: "test_auth_account_id",
		},
		GrantsInfo: &event.GrantsInfo{
			Grants: []event.Grant{
				{
					Grant:   "test_grant",
					ScopeId: "test_grant_scope_id",
				},
			},
		},
	}
	testReq := &event.Request{
		Operation: "POST",
		Endpoint:  "/v1/hosts",
		Details: &pbs.TestAuthenticateRequest{
			AuthMethodId: "test_1234567890",
			TokenType:    "test-cookie",
			Command:      "test-command",
			Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
				"password": structpb.NewStringValue("fido"),
			}},
		},
	}

	testResp := &event.Response{
		StatusCode: 200,
		Details: &pbs.TestAuthenticateResponse{
			Command: "test-command",
			Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
				"token": structpb.NewStringValue("test-token"),
			}},
		},
	}

	tests := []struct {
		name              string
		auditOpts         [][]event.Option
		wantAudit         *testAudit
		ctx               context.Context
		auditSinkFileName string
		setup             func() error
		cleanup           func()
		noOperation       bool
		noFlush           bool
		wantErrIs         error
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
			wantErrIs:       event.ErrInvalidParameter,
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
			wantErrIs:       event.ErrInvalidParameter,
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
			wantErrIs:       event.ErrInvalidParameter,
			wantErrContains: "missing both context and system eventer",
		},
		{
			name:    "use-syseventer",
			noFlush: true,
			ctx: func() context.Context {
				ctx, err := event.NewCorrelationIdContext(context.Background(), corId)
				require.NoError(t, err)
				return ctx
			}(),
			auditOpts: [][]event.Option{
				{
					event.WithAuth(
						func() *event.Auth {
							dup, err := copystructure.Copy(testAuth)
							require.NoError(t, err)
							return dup.(*event.Auth)
						}(),
					),
					event.WithRequest(
						func() *event.Request {
							dup, err := copystructure.Copy(testReq)
							require.NoError(t, err)
							return dup.(*event.Request)
						}(),
					),
				},
			},
			wantAudit: &testAudit{
				Auth: func() *event.Auth {
					dup, err := copystructure.Copy(testAuth)
					require.NoError(t, err)
					dup.(*event.Auth).UserEmail = encrypt.RedactedData
					dup.(*event.Auth).UserName = encrypt.RedactedData
					return dup.(*event.Auth)
				}(),
				Request: func() *event.Request {
					dup, err := copystructure.Copy(testReq)
					require.NoError(t, err)
					dup.(*event.Request).Details.(*pbs.TestAuthenticateRequest).Attributes = &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"password": structpb.NewStringValue(encrypt.RedactedData),
						},
					}
					return dup.(*event.Request)
				}(),
				CorrelationId: corId,
			},
			setup: func() error {
				return event.InitSysEventer(testLogger, testLock, "use-syseventer", event.WithEventerConfig(&c.EventerConfig))
			},
			cleanup:           func() { event.TestResetSystEventer(t) },
			auditSinkFileName: c.AllEvents.Name(),
		},
		{
			name:    "use-syseventer-with-cancelled-ctx",
			noFlush: true,
			ctx: func() context.Context {
				ctx, cancel := context.WithCancel(context.Background())
				ctx, err = event.NewCorrelationIdContext(ctx, corId)
				require.NoError(t, err)
				defer cancel()
				return ctx
			}(),
			auditOpts: [][]event.Option{
				{
					event.WithAuth(testAuth),
					event.WithRequest(testReq),
				},
			},
			wantAudit: &testAudit{
				Auth: func() *event.Auth {
					dup, err := copystructure.Copy(testAuth)
					require.NoError(t, err)
					dup.(*event.Auth).UserEmail = encrypt.RedactedData
					dup.(*event.Auth).UserName = encrypt.RedactedData
					return dup.(*event.Auth)
				}(),
				Request: func() *event.Request {
					dup, err := copystructure.Copy(testReq)
					require.NoError(t, err)
					dup.(*event.Request).Details.(*pbs.TestAuthenticateRequest).Attributes = &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"password": structpb.NewStringValue(encrypt.RedactedData),
						},
					}
					return dup.(*event.Request)
				}(),
				CorrelationId: corId,
			},
			setup: func() error {
				return event.InitSysEventer(testLogger, testLock, "use-syseventer", event.WithEventerConfig(&c.EventerConfig))
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
			wantAudit: &testAudit{
				Id:            "411",
				CorrelationId: corId,
				Auth: func() *event.Auth {
					dup, err := copystructure.Copy(testAuth)
					require.NoError(t, err)
					dup.(*event.Auth).UserEmail = encrypt.RedactedData
					dup.(*event.Auth).UserName = encrypt.RedactedData
					return dup.(*event.Auth)
				}(),
				Request: func() *event.Request {
					dup, err := copystructure.Copy(testReq)
					require.NoError(t, err)
					dup.(*event.Request).Details.(*pbs.TestAuthenticateRequest).Attributes = &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"password": structpb.NewStringValue(encrypt.RedactedData),
						},
					}
					return dup.(*event.Request)
				}(),
				Response: func() *event.Response {
					dup, err := copystructure.Copy(testResp)
					require.NoError(t, err)
					dup.(*event.Response).Details.(*pbs.TestAuthenticateResponse).Attributes = &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"token": structpb.NewStringValue(encrypt.RedactedData),
						},
					}
					return dup.(*event.Response)
				}(),
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
				if tt.wantErrIs != nil {
					assert.ErrorIs(err, tt.wantErrIs)
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

				b, err := os.ReadFile(tt.auditSinkFileName)
				require.NoError(err)
				gotAudit := &cloudevents.Event{}
				err = json.Unmarshal(b, gotAudit)
				require.NoErrorf(err, "json: %s", string(b))

				actualJson, err := json.Marshal(gotAudit)
				require.NoError(err)
				wantEvent := cloudevents.Event{
					ID:              gotAudit.ID,
					Source:          gotAudit.Source,
					SpecVersion:     gotAudit.SpecVersion,
					DataContentType: gotAudit.DataContentType,
					Time:            gotAudit.Time,
					Type:            "audit",
					Data: map[string]any{
						"auth":           tt.wantAudit.Auth,
						"id":             gotAudit.Data.(map[string]any)["id"],
						"timestamp":      now,
						"request":        tt.wantAudit.Request,
						"type":           apiRequest,
						"version":        testAuditVersion,
						"correlation_id": tt.wantAudit.CorrelationId,
					},
				}
				if tt.wantAudit.Id != "" {
					wantEvent.Data.(map[string]any)["id"] = tt.wantAudit.Id
					wantEvent.Data.(map[string]any)["request_info"] = event.RequestInfo{
						Id: gotAudit.Data.(map[string]any)["request_info"].(map[string]any)["id"].(string),
					}
				}
				if tt.wantAudit.Response != nil {
					wantEvent.Data.(map[string]any)["response"] = tt.wantAudit.Response
				}
				wantJson, err := json.Marshal(wantEvent)
				require.NoError(err)

				assert.JSONEq(string(wantJson), string(actualJson))
			}
		})
	}
	t.Run("not-enabled", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		c := event.TestEventerConfig(t, "WriteAudit")
		c.EventerConfig.AuditEnabled = false
		testLock := &sync.Mutex{}
		e, err := event.NewEventer(testLogger, testLock, "not-enabled", c.EventerConfig)
		require.NoError(err)

		testCtx, err := event.NewEventerContext(context.Background(), e)
		require.NoError(err)
		testCtx, err = event.NewRequestInfoContext(testCtx, info)
		require.NoError(err)

		require.NoError(event.WriteAudit(testCtx, "not-enabled", event.WithRequest(testReq), event.WithFlush()))
		b, err := os.ReadFile(c.AllEvents.Name())
		assert.NoError(err)
		assert.Len(b, 0)
	})
}

func Test_WriteError(t *testing.T) {
	// this test and its subtests cannot be run in parallel because of it's
	// dependency on the sysEventer
	now := time.Now()

	c := event.TestEventerConfig(t, "WriteAudit")
	testLock := &sync.Mutex{}
	testLogger := testLogger(t, testLock)
	e, err := event.NewEventer(testLogger, testLock, "Test_WriteError", c.EventerConfig, event.WithNow(now))
	require.NoError(t, err)

	info := &event.RequestInfo{Id: "867-5309", EventId: "411"}

	testCtx, err := event.NewEventerContext(context.Background(), e)
	require.NoError(t, err)
	testCtx, err = event.NewRequestInfoContext(testCtx, info)
	require.NoError(t, err)

	testCtxNoInfoId, err := event.NewEventerContext(context.Background(), e)
	require.NoError(t, err)
	noId := &event.RequestInfo{Id: "867-5309", EventId: "411"}
	testCtxNoInfoId, err = event.NewRequestInfoContext(testCtxNoInfoId, noId)
	require.NoError(t, err)
	noId.Id = ""
	noId.EventId = ""

	testError := fakeError{
		Msg:  "test",
		Code: "code",
	}

	tests := []struct {
		name            string
		ctx             context.Context
		e               error
		opt             []event.Option
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
			e:           &testError,
			noOperation: true,
			noOutput:    true,
		},
		{
			name:            "no-ctx-eventer-and-syseventer-not-initialized",
			ctx:             context.Background(),
			e:               &testError,
			errSinkFileName: c.ErrorEvents.Name(),
			noOutput:        true,
		},
		{
			name: "use-syseventer",
			ctx:  context.Background(),
			e:    &testError,
			setup: func() error {
				return event.InitSysEventer(testLogger, testLock, "use-syseventer", event.WithEventerConfig(&c.EventerConfig))
			},
			cleanup:         func() { event.TestResetSystEventer(t) },
			errSinkFileName: c.ErrorEvents.Name(),
		},
		{
			name: "use-syseventer-with-cancelled-ctx",
			ctx: func() context.Context {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				return ctx
			}(),
			e: &testError,
			setup: func() error {
				return event.InitSysEventer(testLogger, testLock, "use-syseventer", event.WithEventerConfig(&c.EventerConfig))
			},
			cleanup:         func() { event.TestResetSystEventer(t) },
			errSinkFileName: c.ErrorEvents.Name(),
		},
		{
			name: "no-info-id",
			ctx:  testCtxNoInfoId,
			e:    &testError,
			info: &event.RequestInfo{},
			setup: func() error {
				return event.InitSysEventer(testLogger, testLock, "no-info-id", event.WithEventerConfig(&c.EventerConfig))
			},
			cleanup:         func() { event.TestResetSystEventer(t) },
			errSinkFileName: c.ErrorEvents.Name(),
		},
		{
			name:            "simple",
			ctx:             testCtx,
			e:               &testError,
			info:            info,
			errSinkFileName: c.ErrorEvents.Name(),
		},
		{
			name:            "simple-with-opt",
			ctx:             testCtx,
			e:               &testError,
			opt:             []event.Option{event.WithInfo("test", "info")},
			info:            info,
			errSinkFileName: c.ErrorEvents.Name(),
		},
		{
			name:            "stderrors",
			ctx:             testCtx,
			e:               stderrors.New("test std errors"),
			opt:             []event.Option{event.WithInfo("test", "info")},
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
			event.WriteError(tt.ctx, event.Op(op), tt.e, tt.opt...)
			if tt.errSinkFileName != "" {
				defer func() { _ = os.WriteFile(tt.errSinkFileName, nil, 0o666) }()
				b, err := os.ReadFile(tt.errSinkFileName)
				require.NoError(err)

				if tt.noOutput {
					assert.Lenf(b, 0, "should be an empty file: %s", string(b))
					return
				}

				gotError := &cloudevents.Event{}
				err = json.Unmarshal(b, gotError)
				require.NoErrorf(err, "json: %s", string(b))

				if _, ok := gotError.Data.(map[string]any)["error_fields"].(map[string]any)["Msg"]; ok {
					actualError := fakeError{
						Msg:  gotError.Data.(map[string]any)["error_fields"].(map[string]any)["Msg"].(string),
						Code: gotError.Data.(map[string]any)["error_fields"].(map[string]any)["Code"].(string),
					}
					assert.Equal(tt.e, &actualError)
				}

			}
		})
	}
}

type fakeError struct {
	Code string
	Msg  string
}

func (f *fakeError) Error() string {
	return f.Msg
}

func Test_WriteSysEvent(t *testing.T) {
	// this test and its subtests cannot be run in parallel because of it's
	// dependency on the sysEventer

	ctx := context.Background()
	c := event.TestEventerConfig(t, "Test_WriteSysEvent")
	testLock := &sync.Mutex{}
	testLogger := testLogger(t, testLock)

	tests := []struct {
		name         string
		ctx          context.Context
		data         []any
		msg          string
		info         *event.RequestInfo
		setup        func() error
		cleanup      func()
		noOperation  bool
		sinkFileName string
		noOutput     bool
	}{
		{
			name:     "no-data",
			ctx:      ctx,
			noOutput: true,
		},
		{
			name:        "missing-caller",
			ctx:         ctx,
			msg:         "hello",
			data:        []any{"data", "test-data"},
			noOperation: true,
		},
		{
			name:         "syseventer-not-initialized",
			ctx:          context.Background(),
			msg:          "hello",
			data:         []any{"data", "test-data"},
			sinkFileName: c.AllEvents.Name(),
			noOutput:     true,
		},
		{
			name: "use-syseventer",
			ctx:  context.Background(),
			msg:  "hello",
			data: []any{"data", "test-data", event.ServerName, "test-server", event.ServerAddress, "localhost"},
			setup: func() error {
				return event.InitSysEventer(testLogger, testLock, "use-syseventer", event.WithEventerConfig(&c.EventerConfig))
			},
			cleanup:      func() { event.TestResetSystEventer(t) },
			sinkFileName: c.AllEvents.Name(),
		},
		{
			name: "use-syseventer-with-cancelled-ctx",
			ctx: func() context.Context {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				return ctx
			}(),
			msg:  "hello",
			data: []any{"data", "test-data", event.ServerName, "test-server", event.ServerAddress, "localhost"},
			setup: func() error {
				return event.InitSysEventer(testLogger, testLock, "use-syseventer", event.WithEventerConfig(&c.EventerConfig))
			},
			cleanup:      func() { event.TestResetSystEventer(t) },
			sinkFileName: c.AllEvents.Name(),
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
			event.WriteSysEvent(tt.ctx, event.Op(op), tt.msg, tt.data...)
			if tt.sinkFileName != "" {
				defer func() { _ = os.WriteFile(tt.sinkFileName, nil, 0o666) }()
				b, err := os.ReadFile(tt.sinkFileName)
				require.NoError(err)

				if tt.noOutput {
					assert.Lenf(b, 0, "should be an empty file: %s", string(b))
					return
				}

				gotSysEvent := &cloudevents.Event{}
				err = json.Unmarshal(b, gotSysEvent)
				require.NoErrorf(err, "json: %s", string(b))

				expected := event.ConvertArgs(tt.data...)
				expected["msg"] = tt.msg
				assert.Equal(expected, gotSysEvent.Data.(map[string]any)["data"].(map[string]any))
			}
		})
	}
}

func TestConvertArgs(t *testing.T) {
	tests := []struct {
		name string
		args []any
		want map[string]any
	}{
		{
			name: "no-args",
			args: []any{},
			want: nil,
		},
		{
			name: "nil-first-arg",
			args: []any{nil},
			want: map[string]any{
				event.MissingKey: nil,
			},
		},
		{
			name: "odd-number-of-args",
			args: []any{1, 2, 3},
			want: map[string]any{
				"1":              2,
				event.MissingKey: 3,
			},
		},
		{
			name: "struct-key",
			args: []any{[]struct{ name string }{{name: "alice"}}, 1},
			want: map[string]any{
				"[{alice}]": 1,
			},
		},
		{
			name: "test-key-with-stringer",
			args: []any{testIntKeyWithStringer(11), "eleven"},
			want: map[string]any{
				"*11*": "eleven",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			got := event.ConvertArgs(tt.args...)
			assert.Equal(tt.want, got)
		})
	}
}

type testIntKeyWithStringer int

func (ti testIntKeyWithStringer) String() string {
	return fmt.Sprint("*", int(ti), "*")
}

func testLogger(t *testing.T, testLock hclog.Locker) hclog.Logger {
	t.Helper()
	return hclog.New(&hclog.LoggerOptions{
		Mutex:      testLock,
		Name:       "test",
		JSONFormat: true,
	})
}

func Test_NewCorrelationIdContext(t *testing.T) {
	corId, err := uuid.GenerateUUID()
	require.NoError(t, err)

	tests := []struct {
		name            string
		ctx             context.Context
		correlationId   string
		wantErrIs       error
		wantErrContains string
	}{
		{
			name:            "missing-ctx",
			wantErrIs:       event.ErrInvalidParameter,
			wantErrContains: "missing context",
		},
		{
			name:            "missing-correlation-id",
			ctx:             context.Background(),
			wantErrIs:       event.ErrInvalidParameter,
			wantErrContains: "missing correlation id",
		},
		{
			name:          "valid",
			ctx:           context.Background(),
			correlationId: corId,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			ctx, err := event.NewCorrelationIdContext(tt.ctx, tt.correlationId)
			if tt.wantErrIs != nil {
				require.Errorf(err, "should have gotten an error")
				assert.Nilf(ctx, "context should be nil")
				assert.ErrorIs(err, tt.wantErrIs)
				if tt.wantErrContains != "" {
					assert.Contains(err.Error(), tt.wantErrContains)
				}
				return
			}
			require.NoError(err)
			require.NotNil(ctx)
			got, ok := event.CorrelationIdFromContext(ctx)
			require.True(ok)
			assert.Equal(tt.correlationId, got)
		})
	}
}

func Test_CorrelationIdFromContext(t *testing.T) {
	corId, err := uuid.GenerateUUID()
	require.NoError(t, err)
	testCtx, err := event.NewCorrelationIdContext(context.Background(), corId)
	require.NoError(t, err)

	tests := []struct {
		name      string
		ctx       context.Context
		wantCorId string
		wantNotOk bool
	}{
		{
			name:      "missing-ctx",
			wantNotOk: true,
		},
		{
			name:      "no-correlation-id",
			ctx:       context.Background(),
			wantNotOk: true,
		},
		{
			name:      "valid",
			ctx:       testCtx,
			wantCorId: corId,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, ok := event.CorrelationIdFromContext(tt.ctx)
			if tt.wantNotOk {
				require.False(ok)
				assert.Empty(got)
				return
			}
			require.True(ok)
			assert.Equal(tt.wantCorId, got)
		})
	}
}
