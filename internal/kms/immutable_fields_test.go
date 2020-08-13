package kms

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// TODO (jimlambrt 8/2020) define tests for immutable fields in the remaining
// kms tables:
//	kms_database_key
//	kms_database_key_version
//	kms_oplog_key
//	kms_oplog_key_version
//	kms_session_key
//	kms_session_key_version

func TestRootKeyVersion_ImmutableFields(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	w := db.New(conn)

	ts := timestamp.Timestamp{Timestamp: &timestamppb.Timestamp{Seconds: 0, Nanos: 0}}

	org, _ := iam.TestScopes(t, conn)
	rk := TestRootKey(t, conn, org.PublicId)
	new := TestRootKeyVersion(t, conn, wrapper, rk.PrivateId, "test key")

	var tests = []struct {
		name      string
		update    *RootKeyVersion
		fieldMask []string
	}{
		{
			name: "private_id",
			update: func() *RootKeyVersion {
				k := new.Clone().(*RootKeyVersion)
				k.PrivateId = "o_thisIsNotAValidId"
				return k
			}(),
			fieldMask: []string{"PrivateId"},
		},
		{
			name: "create time",
			update: func() *RootKeyVersion {
				k := new.Clone().(*RootKeyVersion)
				k.CreateTime = &ts
				return k
			}(),
			fieldMask: []string{"CreateTime"},
		},
		{
			name: "root_key_id",
			update: func() *RootKeyVersion {
				k := new.Clone().(*RootKeyVersion)
				k.RootKeyId = "o_thisIsNotAValidId"
				return k
			}(),
			fieldMask: []string{"RootKeyId"},
		},
		{
			name: "version",
			update: func() *RootKeyVersion {
				k := new.Clone().(*RootKeyVersion)
				k.Version = uint32(22)
				return k
			}(),
			fieldMask: []string{"Version"},
		},
		{
			name: "key",
			update: func() *RootKeyVersion {
				k := new.Clone().(*RootKeyVersion)
				k.Key = "updated key"
				return k
			}(),
			fieldMask: []string{"CtKey"},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			orig := new.Clone()
			err := w.LookupById(context.Background(), orig)
			require.NoError(err)

			err = tt.update.encrypt(context.Background(), wrapper)
			require.NoError(err)
			rowsUpdated, err := w.Update(context.Background(), tt.update, tt.fieldMask, nil)
			require.Error(err)
			assert.Equal(0, rowsUpdated)

			after := new.Clone()
			err = w.LookupById(context.Background(), after)
			require.NoError(err)

			assert.True(proto.Equal(orig.(*RootKeyVersion), after.(*RootKeyVersion)))

		})
	}
}

func TestRootKey_ImmutableFields(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	w := db.New(conn)

	ts := timestamp.Timestamp{Timestamp: &timestamppb.Timestamp{Seconds: 0, Nanos: 0}}

	org, _ := iam.TestScopes(t, conn)
	new := TestRootKey(t, conn, org.PublicId)

	var tests = []struct {
		name      string
		update    *RootKey
		fieldMask []string
	}{
		{
			name: "private_id",
			update: func() *RootKey {
				k := new.Clone().(*RootKey)
				k.PrivateId = "o_thisIsNotAValidId"
				return k
			}(),
			fieldMask: []string{"PrivateId"},
		},
		{
			name: "create time",
			update: func() *RootKey {
				k := new.Clone().(*RootKey)
				k.CreateTime = &ts
				return k
			}(),
			fieldMask: []string{"CreateTime"},
		},
		{
			name: "scope_id",
			update: func() *RootKey {
				k := new.Clone().(*RootKey)
				k.ScopeId = "o_thisIsNotAValidId"
				return k
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
			assert.Equal(0, rowsUpdated)

			after := new.Clone()
			err = w.LookupById(context.Background(), after)
			require.NoError(err)

			assert.True(proto.Equal(orig.(*RootKey), after.(*RootKey)))

		})
	}
}
