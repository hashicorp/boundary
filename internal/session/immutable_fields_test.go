// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package session

import (
	"context"
	"fmt"
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

	_, _ = iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	session := TestDefaultSession(t, conn, wrapper, iamRepo)
	state := TestState(t, conn, session.PublicId, StatusActive)

	fetchSession := func(ctx context.Context, rw *db.Db, sessionId string, startTime *timestamp.Timestamp) (*State, error) {
		const selectQuery = `
select session_id,
       state,
	   lower(active_time_range) as start_time,
	   upper(active_time_range) as end_time
  from session_state
 where session_id = ?
   and lower(active_time_range) = ?;`
		var states []*State
		rows, err := rw.Query(ctx, selectQuery, []any{sessionId, startTime})
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		for rows.Next() {
			if err := rw.ScanRows(ctx, rows, &states); err != nil {
				return nil, err
			}
		}
		if len(states) != 1 {
			return nil, fmt.Errorf("found %d states, expected 1", len(states))
		}
		return states[0], nil
	}

	tests := []struct {
		name      string
		update    *State
		fieldMask []string
	}{
		{
			name: "session_id",
			update: func() *State {
				s := state.Clone().(*State)
				s.SessionId = "s_thisIsNotAValidId"
				return s
			}(),
			fieldMask: []string{"PublicId"},
		},
		{
			name: "status",
			update: func() *State {
				s := state.Clone().(*State)
				s.Status = "canceling"
				return s
			}(),
			fieldMask: []string{"Status"},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			assert, require := assert.New(t), require.New(t)
			orig, err := fetchSession(ctx, rw, state.SessionId, state.StartTime)
			require.NoError(err)

			rowsUpdated, err := rw.Update(context.Background(), tt.update, tt.fieldMask, nil, db.WithSkipVetForWrite(true))
			require.Error(err)
			assert.Equal(0, rowsUpdated)

			after, err := fetchSession(ctx, rw, state.SessionId, state.StartTime)
			require.NoError(err)
			assert.Equal(orig, after)
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
