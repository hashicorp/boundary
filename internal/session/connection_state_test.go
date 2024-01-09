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

func TestConnectionState_Create(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	session := TestDefaultSession(t, conn, wrapper, iamRepo)
	connection := TestConnection(t, conn, session.PublicId, "127.0.0.1", 443, "127.0.0.1", 4443, "127.0.0.1")

	type args struct {
		connectionId string
		status       ConnectionStatus
	}
	tests := []struct {
		name          string
		args          args
		want          *ConnectionState
		wantErr       bool
		wantIsErr     errors.Code
		create        bool
		wantCreateErr bool
	}{
		{
			name: "valid",
			args: args{
				connectionId: connection.PublicId,
				status:       StatusClosed,
			},
			want: &ConnectionState{
				ConnectionId: connection.PublicId,
				Status:       StatusClosed,
			},
			create: true,
		},
		{
			name: "empty-connectionId",
			args: args{
				status: StatusClosed,
			},
			wantErr:   true,
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "empty-status",
			args: args{
				connectionId: connection.PublicId,
			},
			wantErr:   true,
			wantIsErr: errors.InvalidParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewConnectionState(ctx, tt.args.connectionId, tt.args.status)
			if tt.wantErr {
				require.Error(err)
				assert.True(errors.Match(errors.T(tt.wantIsErr), err))
				return
			}
			require.NoError(err)
			assert.Equal(tt.want, got)
			if tt.create {
				err = db.New(conn).Create(ctx, got)
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

func TestConnectionState_Delete(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	s := TestDefaultSession(t, conn, wrapper, iamRepo)
	c := TestConnection(t, conn, s.PublicId, "127.0.0.1", 22, "127.0.0.1", 2222, "127.0.0.1")
	c2 := TestConnection(t, conn, s.PublicId, "127.0.0.1", 22, "127.0.0.1", 2222, "127.0.0.1")

	tests := []struct {
		name                    string
		state                   *ConnectionState
		deleteConnectionStateId string
		wantRowsDeleted         int
		wantErr                 bool
		wantErrMsg              string
	}{
		{
			name:            "valid",
			state:           TestConnectionState(t, conn, c.PublicId, StatusClosed),
			wantErr:         false,
			wantRowsDeleted: 1,
		},
		{
			name:  "bad-id",
			state: TestConnectionState(t, conn, c2.PublicId, StatusClosed),
			deleteConnectionStateId: func() string {
				id, err := db.NewPublicId(ctx, ConnectionStatePrefix)
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

			var initialState ConnectionState
			err := rw.LookupWhere(context.Background(), &initialState, "connection_id = ? and state = ?", []any{tt.state.ConnectionId, tt.state.Status})
			require.NoError(err)

			deleteState := allocConnectionState()
			if tt.deleteConnectionStateId != "" {
				deleteState.ConnectionId = tt.deleteConnectionStateId
			} else {
				deleteState.ConnectionId = tt.state.ConnectionId
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
			foundState := allocConnectionState()
			err = rw.LookupWhere(ctx, &foundState, "connection_id = ? and start_time = ?", []any{tt.state.ConnectionId, initialState.StartTime})
			require.Error(err)
			assert.True(errors.IsNotFoundError(err))
		})
	}
}

func TestConnectionState_Clone(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	t.Run("valid", func(t *testing.T) {
		assert := assert.New(t)
		s := TestDefaultSession(t, conn, wrapper, iamRepo)
		c := TestConnection(t, conn, s.PublicId, "127.0.0.1", 22, "127.0.0.1", 2222, "127.0.0.1")
		state := TestConnectionState(t, conn, c.PublicId, StatusConnected)
		cp := state.Clone()
		assert.Equal(cp.(*ConnectionState), state)
	})
	t.Run("not-equal", func(t *testing.T) {
		assert := assert.New(t)
		s := TestDefaultSession(t, conn, wrapper, iamRepo)
		c := TestConnection(t, conn, s.PublicId, "127.0.0.1", 22, "127.0.0.1", 2222, "127.0.0.1")
		state := TestConnectionState(t, conn, c.PublicId, StatusConnected)
		state2 := TestConnectionState(t, conn, c.PublicId, StatusConnected)

		cp := state.Clone()
		assert.NotEqual(cp.(*ConnectionState), state2)
	})
}

func TestConnectionState_SetTableName(t *testing.T) {
	t.Parallel()
	defaultTableName := defaultConnectionStateTableName
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
			def := allocConnectionState()
			require.Equal(defaultTableName, def.TableName())
			s := allocConnectionState()
			s.SetTableName(tt.setNameTo)
			assert.Equal(tt.want, s.TableName())
		})
	}
}
