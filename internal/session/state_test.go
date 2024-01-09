// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package session

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestState_Create(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	session := TestDefaultSession(t, conn, wrapper, iamRepo)

	type args struct {
		sessionId string
		status    Status
	}

	tests := []struct {
		name          string
		args          args
		want          *State
		wantErr       bool
		wantIsErr     errors.Code
		create        bool
		wantCreateErr bool
	}{
		{
			name: "valid",
			args: args{
				sessionId: session.PublicId,
				status:    StatusActive,
			},
			want: &State{
				SessionId: session.PublicId,
				Status:    StatusActive,
			},
			create: true,
		},
		{
			name: "empty-sessionId",
			args: args{
				status: StatusPending,
			},
			wantErr:   true,
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "empty-status",
			args: args{
				sessionId: session.PublicId,
			},
			wantErr:   true,
			wantIsErr: errors.InvalidParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewState(context.Background(), tt.args.sessionId, tt.args.status)
			if tt.wantErr {
				require.Error(err)
				assert.True(errors.Match(errors.T(tt.wantIsErr), err))
				return
			}
			require.NoError(err)
			assert.Equal(tt.want, got)
			if tt.create {
				err = db.New(conn).Create(context.Background(), got)
				if tt.wantCreateErr {
					assert.Error(err)
					return
				} else {
					assert.NoError(err)
				}
			}
		})
	}
}

func TestState_Delete(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	session := TestDefaultSession(t, conn, wrapper, iamRepo)
	session2 := TestDefaultSession(t, conn, wrapper, iamRepo)

	tests := []struct {
		name            string
		state           *State
		deleteStateId   string
		wantRowsDeleted int
		wantErr         bool
		wantErrMsg      string
	}{
		{
			name:            "valid",
			state:           TestState(t, conn, session.PublicId, StatusTerminated),
			wantErr:         false,
			wantRowsDeleted: 1,
		},
		{
			name:  "bad-id",
			state: TestState(t, conn, session2.PublicId, StatusTerminated),
			deleteStateId: func() string {
				id, err := db.NewPublicId(ctx, StatePrefix)
				require.NoError(t, err)
				return id
			}(),
			wantErr:         false,
			wantRowsDeleted: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			var initialState State
			err := rw.LookupWhere(ctx, &initialState, "session_id = ? and state = ?", []any{tt.state.SessionId, tt.state.Status})
			require.NoError(err)

			deleteState := allocState()
			if tt.deleteStateId != "" {
				deleteState.SessionId = tt.deleteStateId
			} else {
				deleteState.SessionId = tt.state.SessionId
			}
			deleteState.StartTime = initialState.StartTime
			deletedRows, err := rw.Delete(ctx, &deleteState)
			if tt.wantErr {
				require.Error(err)
				return
			}
			require.NoError(err)
			if tt.wantRowsDeleted == 0 {
				assert.Equal(tt.wantRowsDeleted, deletedRows)
				return
			}
			assert.Equal(tt.wantRowsDeleted, deletedRows)
			foundState := allocState()
			err = rw.LookupWhere(ctx, &foundState, "session_id = ? and start_time = ?", []any{tt.state.SessionId, initialState.StartTime})
			require.Error(err)
			assert.True(errors.IsNotFoundError(err))
		})
	}
}

func TestState_Clone(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	t.Run("valid", func(t *testing.T) {
		assert := assert.New(t)
		s := TestDefaultSession(t, conn, wrapper, iamRepo)
		state := TestState(t, conn, s.PublicId, StatusActive)
		cp := state.Clone()
		assert.Equal(cp.(*State), state)
	})
	t.Run("not-equal", func(t *testing.T) {
		assert := assert.New(t)
		s := TestDefaultSession(t, conn, wrapper, iamRepo)
		s2 := TestDefaultSession(t, conn, wrapper, iamRepo)
		state := TestState(t, conn, s.PublicId, StatusActive)
		state2 := TestState(t, conn, s2.PublicId, StatusActive)

		cp := state.Clone()
		assert.NotEqual(cp.(*State), state2)
	})
}

func TestState_SetTableName(t *testing.T) {
	t.Parallel()
	defaultTableName := defaultStateTableName
	tests := []struct {
		name      string
		setNameTo string
		want      string
	}{
		{
			name:      "new-name",
			setNameTo: "new-name",
			want:      "new-name",
		},
		{
			name:      "reset to default",
			setNameTo: "",
			want:      defaultTableName,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			def := allocState()
			require.Equal(defaultTableName, def.TableName())
			s := allocState()
			s.SetTableName(tt.setNameTo)
			assert.Equal(tt.want, s.TableName())
		})
	}
}
