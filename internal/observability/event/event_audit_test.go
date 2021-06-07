package event

import (
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/eventlogger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_newAudit(t *testing.T) {
	t.Parallel()
	testNow := time.Now()

	tests := []struct {
		name         string
		fromOp       Op
		opts         []Option
		want         *audit
		wantErrMatch *errors.Template
	}{
		{
			name:         "missing-op",
			wantErrMatch: errors.T(errors.InvalidParameter),
		},
		{
			name:   "valid-no-opts",
			fromOp: "valid-no-opts",
			want: &audit{
				Version: auditVersion,
				Type:    string(apiRequest),
			},
		},
		{
			name:   "all-opts",
			fromOp: "all-opts",
			opts: []Option{
				WithId("all-opts"),
				WithNow(testNow),
				WithRequestInfo(TestRequestInfo(t)),
				WithAuth(testAuth(t)),
				WithRequest(testRequest(t)),
				WithResponse(testResponse(t)),
				WithFlush(),
			},
			want: &audit{
				Id:          "all-opts",
				Version:     auditVersion,
				Type:        string(apiRequest),
				Timestamp:   testNow,
				RequestInfo: TestRequestInfo(t),
				Auth:        testAuth(t),
				Request:     testRequest(t),
				Response:    testResponse(t),
				Flush:       true,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := newAudit(tt.fromOp, tt.opts...)
			if tt.wantErrMatch != nil {
				require.Error(err)
				assert.Nil(got)
				assert.True(errors.Match(tt.wantErrMatch, err))
				return
			}
			require.NoError(err)
			require.NotNil(got)
			opts := getOpts(tt.opts...)
			if opts.withId == "" {
				tt.want.Id = got.Id
			}
			if opts.withNow.IsZero() {
				tt.want.Timestamp = got.Timestamp
			}
			assert.Equal(tt.want, got)
		})
	}
}

func TestAudit_validate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name            string
		id              string
		wantErrMatch    *errors.Template
		wantErrContains string
	}{
		{
			name:            "missing-id",
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing id",
		},
		{
			name: "valid",
			id:   "valid",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			a := audit{Id: tt.id}
			err := a.validate()
			if tt.wantErrMatch != nil {
				require.Error(err)
				assert.True(errors.Match(tt.wantErrMatch, err))
				if tt.wantErrContains != "" {
					assert.Contains(err.Error(), tt.wantErrContains)
				}
				return
			}
			assert.NoError(err)
		})
	}
}

func TestAudit_EventType(t *testing.T) {
	t.Parallel()
	a := &audit{}
	assert.Equal(t, string(AuditType), a.EventType())
}

func TestAudit_GetID(t *testing.T) {
	t.Parallel()
	a := &audit{Id: "test"}
	assert.Equal(t, "test", a.GetID())
}

func TestAudit_FlushEvent(t *testing.T) {
	t.Parallel()
	a := &audit{Flush: true}
	assert.True(t, a.FlushEvent())
	a.Flush = false
	assert.False(t, a.FlushEvent())
}

func TestAudit_ComposeFrom(t *testing.T) {
	t.Parallel()
	testNow := time.Now()
	tests := []struct {
		name            string
		events          []*eventlogger.Event
		want            audit
		wantErrMatch    *errors.Template
		wantErrContains string
	}{
		{
			name:            "missing-events",
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing events",
		},
		{
			name: "not-an-audit",
			events: []*eventlogger.Event{{
				Payload: struct{}{},
			}},
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "not an audit payload",
		},
		{
			name: "invalid-type",
			events: []*eventlogger.Event{
				{
					Payload: &audit{
						Id:      "test-id",
						Version: auditVersion,
						Type:    "invalid-type",
					},
				},
			},
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "invalid type",
		},
		{
			name: "invalid-version",
			events: []*eventlogger.Event{
				{
					Payload: &audit{
						Id:      "test-id",
						Version: "invalid-version",
						Type:    string(apiRequest),
					},
				},
			},
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "invalid version",
		},
		{
			name: "invalid-id",
			events: []*eventlogger.Event{
				{
					Payload: &audit{
						Id:      "invalid-id",
						Version: auditVersion,
						Type:    string(apiRequest),
					},
				},
				{
					Payload: &audit{
						Id:      "bad-id",
						Version: auditVersion,
						Type:    string(apiRequest),
					},
				},
			},
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "invalid id",
		},
		{
			name: "valid",
			events: []*eventlogger.Event{
				{
					Payload: &audit{
						Id:          "valid",
						Version:     auditVersion,
						Type:        string(apiRequest),
						Timestamp:   testNow,
						Auth:        testAuth(t),
						RequestInfo: TestRequestInfo(t),
					},
				},
				{
					Payload: &audit{
						Id:        "valid",
						Version:   auditVersion,
						Type:      string(apiRequest),
						Timestamp: testNow,
						Request:   testRequest(t),
					},
				},
				{
					Payload: &audit{
						Id:        "valid",
						Version:   auditVersion,
						Type:      string(apiRequest),
						Timestamp: testNow,
						Response:  testResponse(t),
					},
				},
			},
			want: audit{
				Id:          "valid",
				Version:     auditVersion,
				Type:        string(apiRequest),
				Timestamp:   testNow,
				Auth:        testAuth(t),
				Request:     testRequest(t),
				Response:    testResponse(t),
				RequestInfo: TestRequestInfo(t),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			a := &audit{}
			gotType, gotAudit, err := a.ComposeFrom(tt.events)
			if tt.wantErrMatch != nil {
				require.Error(err)
				assert.Nil(gotAudit)
				assert.True(errors.Match(tt.wantErrMatch, err))
				if tt.wantErrContains != "" {
					assert.Contains(err.Error(), tt.wantErrContains)
				}
				return
			}
			require.NoError(err)
			require.NotNil(gotAudit)
			assert.Equal(eventlogger.EventType(a.EventType()), gotType)
			tt.want.Timestamp = gotAudit.(audit).Timestamp
			assert.Equal(tt.want, gotAudit)
		})
	}
}
