// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package session

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestSession_ImmutableFields(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	rw := db.New(conn)
	iamRepo := iam.TestRepo(t, conn, wrapper)

	ts := timestamp.Timestamp{Timestamp: &timestamppb.Timestamp{Seconds: 0, Nanos: 0}}

	_, _ = iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	new := TestDefaultSession(t, conn, wrapper, iamRepo)

	tests := []struct {
		name      string
		update    *Session
		fieldMask []string
	}{
		{
			name: "public_id",
			update: func() *Session {
				s := new.Clone().(*Session)
				s.PublicId = "o_thisIsNotAValidId"
				return s
			}(),
			fieldMask: []string{"PublicId"},
		},
		{
			name: "certificate",
			update: func() *Session {
				s := new.Clone().(*Session)
				s.Certificate = []byte("fake cert for test")
				return s
			}(),
			fieldMask: []string{"Certificate"},
		},
		{
			name: "expiration time",
			update: func() *Session {
				s := new.Clone().(*Session)
				s.ExpirationTime = &ts
				return s
			}(),
			fieldMask: []string{"ExpirationTime"},
		},
		{
			name: "create time",
			update: func() *Session {
				s := new.Clone().(*Session)
				s.CreateTime = &ts
				return s
			}(),
			fieldMask: []string{"CreateTime"},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			orig := new.Clone()
			err := rw.LookupById(context.Background(), orig)
			require.NoError(err)

			rowsUpdated, err := rw.Update(context.Background(), tt.update, tt.fieldMask, nil, db.WithSkipVetForWrite(true))
			require.Error(err)
			assert.Equal(0, rowsUpdated)

			after := new.Clone()
			err = rw.LookupById(context.Background(), after)
			require.NoError(err)

			assert.Equal(orig.(*Session), after)
		})
	}
}

func TestState_ImmutableFields(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)

	ts := timestamp.Timestamp{Timestamp: &timestamppb.Timestamp{Seconds: 0, Nanos: 0}}

	_, _ = iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	session := TestDefaultSession(t, conn, wrapper, iamRepo)
	state := TestState(t, conn, session.PublicId, StatusActive)

	var new State
	err := rw.LookupWhere(context.Background(), &new, "session_id = ? and state = ?", []any{state.SessionId, state.Status})
	require.NoError(t, err)

	tests := []struct {
		name      string
		update    *State
		fieldMask []string
	}{
		{
			name: "session_id",
			update: func() *State {
				s := new.Clone().(*State)
				s.SessionId = "s_thisIsNotAValidId"
				return s
			}(),
			fieldMask: []string{"PublicId"},
		},
		{
			name: "status",
			update: func() *State {
				s := new.Clone().(*State)
				s.Status = "canceling"
				return s
			}(),
			fieldMask: []string{"Status"},
		},
		{
			name: "start time",
			update: func() *State {
				s := new.Clone().(*State)
				s.StartTime = &ts
				return s
			}(),
			fieldMask: []string{"StartTime"},
		},
		{
			name: "previous_end_time",
			update: func() *State {
				s := new.Clone().(*State)
				s.PreviousEndTime = &ts
				return s
			}(),
			fieldMask: []string{"PreviousEndTime"},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			orig := new.Clone()
			err := rw.LookupWhere(context.Background(), orig, "session_id = ? and start_time = ?", []any{new.SessionId, new.StartTime})
			require.NoError(err)

			rowsUpdated, err := rw.Update(context.Background(), tt.update, tt.fieldMask, nil, db.WithSkipVetForWrite(true))
			require.Error(err)
			assert.Equal(0, rowsUpdated)

			after := new.Clone()
			err = rw.LookupWhere(context.Background(), after, "session_id = ? and start_time = ?", []any{new.SessionId, new.StartTime})
			require.NoError(err)
			assert.Equal(orig.(*State), after)
		})
	}
}

func TestConnection_ImmutableFields(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	rw := db.New(conn)
	iamRepo := iam.TestRepo(t, conn, wrapper)

	ts := timestamp.Timestamp{Timestamp: &timestamppb.Timestamp{Seconds: 0, Nanos: 0}}

	_, _ = iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	session := TestDefaultSession(t, conn, wrapper, iamRepo)
	new := TestConnection(t, conn, session.PublicId, "127.0.0.1", 22, "127.0.0.1", 2222, "127.0.0.1")

	tests := []struct {
		name      string
		update    *Connection
		fieldMask []string
	}{
		{
			name: "public_id",
			update: func() *Connection {
				c := new.Clone().(*Connection)
				c.PublicId = "sc_thisIsNotAValidId"
				return c
			}(),
			fieldMask: []string{"PublicId"},
		},
		{
			name: "session_id",
			update: func() *Connection {
				c := new.Clone().(*Connection)
				c.SessionId = "s_thisIsNotAValidId"
				return c
			}(),
			fieldMask: []string{"SessionId"},
		},
		{
			name: "create time",
			update: func() *Connection {
				s := new.Clone().(*Connection)
				s.CreateTime = &ts
				return s
			}(),
			fieldMask: []string{"CreateTime"},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			orig := new.Clone()
			err := rw.LookupById(context.Background(), orig)
			require.NoError(err)

			rowsUpdated, err := rw.Update(context.Background(), tt.update, tt.fieldMask, nil, db.WithSkipVetForWrite(true))
			require.Error(err)
			assert.Equal(0, rowsUpdated)

			after := new.Clone()
			err = rw.LookupById(context.Background(), after)
			require.NoError(err)

			assert.Equal(orig.(*Connection), after)
		})
	}
}
