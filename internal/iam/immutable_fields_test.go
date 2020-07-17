package iam

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/db/timestamp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestScope_ImmutableFields(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	w := db.New(conn)

	ts := timestamp.Timestamp{Timestamp: &timestamppb.Timestamp{Seconds: 0, Nanos: 0}}

	new, _ := TestScopes(t, conn)
	var tests = []struct {
		name           string
		update         *Scope
		fieldMask      []string
		wantErr        bool
		wantRowUpdated int
	}{
		{
			name: "public_id",
			update: func() *Scope {
				u := new.Clone().(*Scope)
				u.PublicId = "o_thisIsNotAValidId"
				return u
			}(),
			fieldMask: []string{"PublicId"},
		},
		{
			name: "create time",
			update: func() *Scope {
				u := new.Clone().(*Scope)
				u.CreateTime = &ts
				return u
			}(),
			fieldMask: []string{"CreateTime"},
		},
		{
			name: "type",
			update: func() *Scope {
				u := new.Clone().(*Scope)
				u.Type = "project"
				return u
			}(),
			fieldMask: []string{"Type"},
		},
		{
			name: "parent_id",
			update: func() *Scope {
				u := new.Clone().(*Scope)
				u.PublicId = "p_thisIsNotAValidId"
				return u
			}(),
			fieldMask: []string{"ParentId"},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			orig := new.Clone()
			err := w.LookupById(context.Background(), orig)
			require.NoError(err)

			rowsUpdated, err := w.Update(context.Background(), tt.update, tt.fieldMask, nil)
			require.Error(err)
			assert.Equal(tt.wantRowUpdated, rowsUpdated)

			after := new.Clone()
			err = w.LookupById(context.Background(), after)
			require.NoError(err)

			assert.True(proto.Equal(orig.(*Scope), after.(*Scope)))

		})
	}
}

func TestConcreteScope_ImmutableFields(t *testing.T) {
	const (
		query  = `select scope_id from {{rep}} where scope_id = $1`
		update = `update {{rep}} set scope_id = $1 where scope_id = $2;`
	)
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	db := conn.DB()

	org, proj := TestScopes(t, conn)

	var tests = []struct {
		name      string
		scopeId   string
		updateTo  string
		tableName string
	}{
		{
			name:      "global",
			scopeId:   "global",
			updateTo:  "o_12345678901",
			tableName: "iam_scope_global",
		},
		{
			name:      "org",
			scopeId:   org.PublicId,
			updateTo:  "o_12345678901",
			tableName: "iam_scope_org",
		},
		{
			name:      "project",
			scopeId:   proj.PublicId,
			updateTo:  "o_12345678901",
			tableName: "iam_scope_project",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			updateStmt := strings.Replace(update, "{{rep}}", tt.tableName, -1)
			queryStmt := strings.Replace(query, "{{rep}}", tt.tableName, -1)

			_, err := db.Exec(updateStmt, tt.updateTo, tt.scopeId)
			assert.Error(err)

			var scopeId string
			err = db.QueryRow(queryStmt, tt.scopeId).Scan(&scopeId)
			assert.NoError(err)
			assert.Equal(tt.scopeId, scopeId)
		})
	}
}

func TestUser_ImmutableFields(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	w := db.New(conn)

	ts := timestamp.Timestamp{Timestamp: &timestamppb.Timestamp{Seconds: 0, Nanos: 0}}

	org, proj := TestScopes(t, conn)
	new := TestUser(t, conn, org.PublicId)

	var tests = []struct {
		name           string
		update         *User
		fieldMask      []string
		wantErr        bool
		wantRowUpdated int
	}{
		{
			name: "public_id",
			update: func() *User {
				u := new.Clone().(*User)
				u.PublicId = "o_thisIsNotAValidId"
				return u
			}(),
			fieldMask: []string{"PublicId"},
		},
		{
			name: "create time",
			update: func() *User {
				u := new.Clone().(*User)
				u.CreateTime = &ts
				return u
			}(),
			fieldMask: []string{"CreateTime"},
		},
		{
			name: "scope id",
			update: func() *User {
				u := new.Clone().(*User)
				u.ScopeId = proj.PublicId
				return u
			}(),
			fieldMask: []string{"ScopeId"},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			orig := new.Clone()
			err := w.LookupById(context.Background(), orig)
			require.NoError(err)

			rowsUpdated, err := w.Update(context.Background(), tt.update, tt.fieldMask, nil)
			require.Error(err)
			assert.Equal(tt.wantRowUpdated, rowsUpdated)

			after := new.Clone()
			err = w.LookupById(context.Background(), after)
			require.NoError(err)

			assert.True(proto.Equal(orig.(*User), after.(*User)))

		})
	}
}

func TestRole_ImmutableFields(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	w := db.New(conn)

	ts := timestamp.Timestamp{Timestamp: &timestamppb.Timestamp{Seconds: 0, Nanos: 0}}

	org, proj := TestScopes(t, conn)
	new := TestRole(t, conn, org.PublicId)

	var tests = []struct {
		name           string
		update         *Role
		fieldMask      []string
		wantErr        bool
		wantRowUpdated int
	}{
		{
			name: "public_id",
			update: func() *Role {
				u := new.Clone().(*Role)
				u.PublicId = "r_thisIsNotAValidId"
				return u
			}(),
			fieldMask: []string{"PublicId"},
		},
		{
			name: "create time",
			update: func() *Role {
				u := new.Clone().(*Role)
				u.CreateTime = &ts
				return u
			}(),
			fieldMask: []string{"CreateTime"},
		},
		{
			name: "scope id",
			update: func() *Role {
				u := new.Clone().(*Role)
				u.ScopeId = proj.PublicId
				return u
			}(),
			fieldMask: []string{"ScopeId"},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			orig := new.Clone()
			err := w.LookupById(context.Background(), orig)
			require.NoError(err)

			rowsUpdated, err := w.Update(context.Background(), tt.update, tt.fieldMask, nil)
			require.Error(err)
			assert.Equal(tt.wantRowUpdated, rowsUpdated)

			after := new.Clone()
			err = w.LookupById(context.Background(), after)
			require.NoError(err)

			assert.True(proto.Equal(orig.(*Role), after.(*Role)))

		})
	}
}
