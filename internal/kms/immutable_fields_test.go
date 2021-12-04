package kms_test

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestOplogKey_ImmutableFields(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)

	ts := timestamp.Timestamp{Timestamp: &timestamppb.Timestamp{Seconds: 0, Nanos: 0}}

	wrapper := db.TestWrapper(t)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	db.TestDeleteWhere(t, conn, kms.AllocRootKey(), "1=1")
	db.TestDeleteWhere(t, conn, kms.AllocOplogKey(), "1=1")
	rk := kms.TestRootKey(t, conn, org.PublicId)
	new := kms.TestOplogKey(t, conn, rk.PrivateId)

	tests := []struct {
		name      string
		update    *kms.OplogKey
		fieldMask []string
	}{
		{
			name: "private_id",
			update: func() *kms.OplogKey {
				k := new.Clone().(*kms.OplogKey)
				k.PrivateId = "o_thisIsNotAValidId"
				return k
			}(),
			fieldMask: []string{"PrivateId"},
		},
		{
			name: "create time",
			update: func() *kms.OplogKey {
				k := new.Clone().(*kms.OplogKey)
				k.CreateTime = &ts
				return k
			}(),
			fieldMask: []string{"CreateTime"},
		},
		{
			name: "root_key_id",
			update: func() *kms.OplogKey {
				k := new.Clone().(*kms.OplogKey)
				k.RootKeyId = "o_thisIsNotAValidId"
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
			err := rw.LookupById(context.Background(), orig)
			require.NoError(err)

			rowsUpdated, err := rw.Update(context.Background(), tt.update, tt.fieldMask, nil, db.WithSkipVetForWrite(true))
			require.Error(err)
			assert.Equal(0, rowsUpdated)

			after := new.Clone()
			err = rw.LookupById(context.Background(), after)
			require.NoError(err)

			assert.True(proto.Equal(orig.(*kms.OplogKey), after.(*kms.OplogKey)))
		})
	}
}

func TestOplogKeyVersion_ImmutableFields(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	rw := db.New(conn)

	ts := timestamp.Timestamp{Timestamp: &timestamppb.Timestamp{Seconds: 0, Nanos: 0}}

	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	db.TestDeleteWhere(t, conn, kms.AllocRootKey(), "1=1")
	rk := kms.TestRootKey(t, conn, org.PublicId)
	_, rkvWrapper := kms.TestRootKeyVersion(t, conn, wrapper, rk.PrivateId)
	dk := kms.TestOplogKey(t, conn, rk.PrivateId)
	new := kms.TestOplogKeyVersion(t, conn, rkvWrapper, dk.PrivateId, []byte("oplog key"))

	tests := []struct {
		name      string
		update    *kms.OplogKeyVersion
		fieldMask []string
	}{
		{
			name: "private_id",
			update: func() *kms.OplogKeyVersion {
				k := new.Clone().(*kms.OplogKeyVersion)
				k.PrivateId = "o_thisIsNotAValidId"
				return k
			}(),
			fieldMask: []string{"PrivateId"},
		},
		{
			name: "create time",
			update: func() *kms.OplogKeyVersion {
				k := new.Clone().(*kms.OplogKeyVersion)
				k.CreateTime = &ts
				return k
			}(),
			fieldMask: []string{"CreateTime"},
		},
		{
			name: "oplog_key_id",
			update: func() *kms.OplogKeyVersion {
				k := new.Clone().(*kms.OplogKeyVersion)
				k.OplogKeyId = "o_thisIsNotAValidId"
				return k
			}(),
			fieldMask: []string{"RootKeyId"},
		},
		{
			name: "root_key_version_id",
			update: func() *kms.OplogKeyVersion {
				k := new.Clone().(*kms.OplogKeyVersion)
				k.RootKeyVersionId = "o_thisIsNotAValidId"
				return k
			}(),
			fieldMask: []string{"RootKeyId"},
		},
		{
			name: "version",
			update: func() *kms.OplogKeyVersion {
				k := new.Clone().(*kms.OplogKeyVersion)
				k.Version = uint32(22)
				return k
			}(),
			fieldMask: []string{"Version"},
		},
		{
			name: "key",
			update: func() *kms.OplogKeyVersion {
				k := new.Clone().(*kms.OplogKeyVersion)
				k.Key = []byte("updated key")
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
			err := rw.LookupById(context.Background(), orig)
			require.NoError(err)

			err = tt.update.Encrypt(context.Background(), wrapper)
			require.NoError(err)
			rowsUpdated, err := rw.Update(context.Background(), tt.update, tt.fieldMask, nil, db.WithSkipVetForWrite(true))
			require.Error(err)
			assert.Equal(0, rowsUpdated)

			after := new.Clone()
			err = rw.LookupById(context.Background(), after)
			require.NoError(err)

			assert.True(proto.Equal(orig.(*kms.OplogKeyVersion), after.(*kms.OplogKeyVersion)))
		})
	}
}

func TestTokenKey_ImmutableFields(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)

	ts := timestamp.Timestamp{Timestamp: &timestamppb.Timestamp{Seconds: 0, Nanos: 0}}

	wrapper := db.TestWrapper(t)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	db.TestDeleteWhere(t, conn, kms.AllocRootKey(), "1=1")
	db.TestDeleteWhere(t, conn, kms.AllocTokenKey(), "1=1")
	rk := kms.TestRootKey(t, conn, org.PublicId)
	new := kms.TestTokenKey(t, conn, rk.PrivateId)

	tests := []struct {
		name      string
		update    *kms.TokenKey
		fieldMask []string
	}{
		{
			name: "private_id",
			update: func() *kms.TokenKey {
				k := new.Clone().(*kms.TokenKey)
				k.PrivateId = "o_thisIsNotAValidId"
				return k
			}(),
			fieldMask: []string{"PrivateId"},
		},
		{
			name: "create time",
			update: func() *kms.TokenKey {
				k := new.Clone().(*kms.TokenKey)
				k.CreateTime = &ts
				return k
			}(),
			fieldMask: []string{"CreateTime"},
		},
		{
			name: "root_key_id",
			update: func() *kms.TokenKey {
				k := new.Clone().(*kms.TokenKey)
				k.RootKeyId = "o_thisIsNotAValidId"
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
			err := rw.LookupById(context.Background(), orig)
			require.NoError(err)

			rowsUpdated, err := rw.Update(context.Background(), tt.update, tt.fieldMask, nil, db.WithSkipVetForWrite(true))
			require.Error(err)
			assert.Equal(0, rowsUpdated)

			after := new.Clone()
			err = rw.LookupById(context.Background(), after)
			require.NoError(err)

			assert.True(proto.Equal(orig.(*kms.TokenKey), after.(*kms.TokenKey)))
		})
	}
}

func TestTokenKeyVersion_ImmutableFields(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	rw := db.New(conn)

	ts := timestamp.Timestamp{Timestamp: &timestamppb.Timestamp{Seconds: 0, Nanos: 0}}

	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	db.TestDeleteWhere(t, conn, kms.AllocRootKey(), "1=1")
	rk := kms.TestRootKey(t, conn, org.PublicId)
	_, rkvWrapper := kms.TestRootKeyVersion(t, conn, wrapper, rk.PrivateId)
	dk := kms.TestTokenKey(t, conn, rk.PrivateId)
	new := kms.TestTokenKeyVersion(t, conn, rkvWrapper, dk.PrivateId, []byte("token key"))

	tests := []struct {
		name      string
		update    *kms.TokenKeyVersion
		fieldMask []string
	}{
		{
			name: "private_id",
			update: func() *kms.TokenKeyVersion {
				k := new.Clone().(*kms.TokenKeyVersion)
				k.PrivateId = "o_thisIsNotAValidId"
				return k
			}(),
			fieldMask: []string{"PrivateId"},
		},
		{
			name: "create time",
			update: func() *kms.TokenKeyVersion {
				k := new.Clone().(*kms.TokenKeyVersion)
				k.CreateTime = &ts
				return k
			}(),
			fieldMask: []string{"CreateTime"},
		},
		{
			name: "token_key_id",
			update: func() *kms.TokenKeyVersion {
				k := new.Clone().(*kms.TokenKeyVersion)
				k.TokenKeyId = "o_thisIsNotAValidId"
				return k
			}(),
			fieldMask: []string{"RootKeyId"},
		},
		{
			name: "root_key_version_id",
			update: func() *kms.TokenKeyVersion {
				k := new.Clone().(*kms.TokenKeyVersion)
				k.RootKeyVersionId = "o_thisIsNotAValidId"
				return k
			}(),
			fieldMask: []string{"RootKeyId"},
		},
		{
			name: "version",
			update: func() *kms.TokenKeyVersion {
				k := new.Clone().(*kms.TokenKeyVersion)
				k.Version = uint32(22)
				return k
			}(),
			fieldMask: []string{"Version"},
		},
		{
			name: "key",
			update: func() *kms.TokenKeyVersion {
				k := new.Clone().(*kms.TokenKeyVersion)
				k.Key = []byte("updated key")
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
			err := rw.LookupById(context.Background(), orig)
			require.NoError(err)

			err = tt.update.Encrypt(context.Background(), wrapper)
			require.NoError(err)
			rowsUpdated, err := rw.Update(context.Background(), tt.update, tt.fieldMask, nil, db.WithSkipVetForWrite(true))
			require.Error(err)
			assert.Equal(0, rowsUpdated)

			after := new.Clone()
			err = rw.LookupById(context.Background(), after)
			require.NoError(err)

			assert.True(proto.Equal(orig.(*kms.TokenKeyVersion), after.(*kms.TokenKeyVersion)))
		})
	}
}

func TestSessionKey_ImmutableFields(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)

	ts := timestamp.Timestamp{Timestamp: &timestamppb.Timestamp{Seconds: 0, Nanos: 0}}

	wrapper := db.TestWrapper(t)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	db.TestDeleteWhere(t, conn, kms.AllocRootKey(), "1=1")
	db.TestDeleteWhere(t, conn, kms.AllocSessionKey(), "1=1")
	rk := kms.TestRootKey(t, conn, org.PublicId)
	new := kms.TestSessionKey(t, conn, rk.PrivateId)

	tests := []struct {
		name      string
		update    *kms.SessionKey
		fieldMask []string
	}{
		{
			name: "private_id",
			update: func() *kms.SessionKey {
				k := new.Clone().(*kms.SessionKey)
				k.PrivateId = "o_thisIsNotAValidId"
				return k
			}(),
			fieldMask: []string{"PrivateId"},
		},
		{
			name: "create time",
			update: func() *kms.SessionKey {
				k := new.Clone().(*kms.SessionKey)
				k.CreateTime = &ts
				return k
			}(),
			fieldMask: []string{"CreateTime"},
		},
		{
			name: "root_key_id",
			update: func() *kms.SessionKey {
				k := new.Clone().(*kms.SessionKey)
				k.RootKeyId = "o_thisIsNotAValidId"
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
			err := rw.LookupById(context.Background(), orig)
			require.NoError(err)

			rowsUpdated, err := rw.Update(context.Background(), tt.update, tt.fieldMask, nil, db.WithSkipVetForWrite(true))
			require.Error(err)
			assert.Equal(0, rowsUpdated)

			after := new.Clone()
			err = rw.LookupById(context.Background(), after)
			require.NoError(err)

			assert.True(proto.Equal(orig.(*kms.SessionKey), after.(*kms.SessionKey)))
		})
	}
}

func TestSessionKeyVersion_ImmutableFields(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	rw := db.New(conn)

	ts := timestamp.Timestamp{Timestamp: &timestamppb.Timestamp{Seconds: 0, Nanos: 0}}

	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	db.TestDeleteWhere(t, conn, kms.AllocRootKey(), "1=1")
	rk := kms.TestRootKey(t, conn, org.PublicId)
	_, rkvWrapper := kms.TestRootKeyVersion(t, conn, wrapper, rk.PrivateId)
	dk := kms.TestSessionKey(t, conn, rk.PrivateId)
	new := kms.TestSessionKeyVersion(t, conn, rkvWrapper, dk.PrivateId, []byte("session key"))

	tests := []struct {
		name      string
		update    *kms.SessionKeyVersion
		fieldMask []string
	}{
		{
			name: "private_id",
			update: func() *kms.SessionKeyVersion {
				k := new.Clone().(*kms.SessionKeyVersion)
				k.PrivateId = "o_thisIsNotAValidId"
				return k
			}(),
			fieldMask: []string{"PrivateId"},
		},
		{
			name: "create time",
			update: func() *kms.SessionKeyVersion {
				k := new.Clone().(*kms.SessionKeyVersion)
				k.CreateTime = &ts
				return k
			}(),
			fieldMask: []string{"CreateTime"},
		},
		{
			name: "Session_key_id",
			update: func() *kms.SessionKeyVersion {
				k := new.Clone().(*kms.SessionKeyVersion)
				k.SessionKeyId = "o_thisIsNotAValidId"
				return k
			}(),
			fieldMask: []string{"RootKeyId"},
		},
		{
			name: "root_key_version_id",
			update: func() *kms.SessionKeyVersion {
				k := new.Clone().(*kms.SessionKeyVersion)
				k.RootKeyVersionId = "o_thisIsNotAValidId"
				return k
			}(),
			fieldMask: []string{"RootKeyId"},
		},
		{
			name: "version",
			update: func() *kms.SessionKeyVersion {
				k := new.Clone().(*kms.SessionKeyVersion)
				k.Version = uint32(22)
				return k
			}(),
			fieldMask: []string{"Version"},
		},
		{
			name: "key",
			update: func() *kms.SessionKeyVersion {
				k := new.Clone().(*kms.SessionKeyVersion)
				k.Key = []byte("updated key")
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
			err := rw.LookupById(context.Background(), orig)
			require.NoError(err)

			err = tt.update.Encrypt(context.Background(), wrapper)
			require.NoError(err)
			rowsUpdated, err := rw.Update(context.Background(), tt.update, tt.fieldMask, nil, db.WithSkipVetForWrite(true))
			require.Error(err)
			assert.Equal(0, rowsUpdated)

			after := new.Clone()
			err = rw.LookupById(context.Background(), after)
			require.NoError(err)

			assert.True(proto.Equal(orig.(*kms.SessionKeyVersion), after.(*kms.SessionKeyVersion)))
		})
	}
}

func TestRootKeyVersion_ImmutableFields(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	rw := db.New(conn)

	ts := timestamp.Timestamp{Timestamp: &timestamppb.Timestamp{Seconds: 0, Nanos: 0}}

	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	db.TestDeleteWhere(t, conn, kms.AllocRootKey(), "1=1")
	db.TestDeleteWhere(t, conn, kms.AllocRootKeyVersion(), "1=1")
	rk := kms.TestRootKey(t, conn, org.PublicId)
	new, _ := kms.TestRootKeyVersion(t, conn, wrapper, rk.PrivateId)

	tests := []struct {
		name      string
		update    *kms.RootKeyVersion
		fieldMask []string
	}{
		{
			name: "private_id",
			update: func() *kms.RootKeyVersion {
				k := new.Clone().(*kms.RootKeyVersion)
				k.PrivateId = "o_thisIsNotAValidId"
				return k
			}(),
			fieldMask: []string{"PrivateId"},
		},
		{
			name: "create time",
			update: func() *kms.RootKeyVersion {
				k := new.Clone().(*kms.RootKeyVersion)
				k.CreateTime = &ts
				return k
			}(),
			fieldMask: []string{"CreateTime"},
		},
		{
			name: "root_key_id",
			update: func() *kms.RootKeyVersion {
				k := new.Clone().(*kms.RootKeyVersion)
				k.RootKeyId = "o_thisIsNotAValidId"
				return k
			}(),
			fieldMask: []string{"RootKeyId"},
		},
		{
			name: "version",
			update: func() *kms.RootKeyVersion {
				k := new.Clone().(*kms.RootKeyVersion)
				k.Version = uint32(22)
				return k
			}(),
			fieldMask: []string{"Version"},
		},
		{
			name: "key",
			update: func() *kms.RootKeyVersion {
				k := new.Clone().(*kms.RootKeyVersion)
				k.Key = []byte("updated key")
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
			err := rw.LookupById(context.Background(), orig)
			require.NoError(err)

			err = tt.update.Encrypt(context.Background(), wrapper)
			require.NoError(err)
			rowsUpdated, err := rw.Update(context.Background(), tt.update, tt.fieldMask, nil, db.WithSkipVetForWrite(true))
			require.Error(err)
			assert.Equal(0, rowsUpdated)

			after := new.Clone()
			err = rw.LookupById(context.Background(), after)
			require.NoError(err)

			assert.True(proto.Equal(orig.(*kms.RootKeyVersion), after.(*kms.RootKeyVersion)))
		})
	}
}

func TestRootKey_ImmutableFields(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)

	ts := timestamp.Timestamp{Timestamp: &timestamppb.Timestamp{Seconds: 0, Nanos: 0}}

	wrapper := db.TestWrapper(t)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	db.TestDeleteWhere(t, conn, kms.AllocRootKey(), "1=1")
	new := kms.TestRootKey(t, conn, org.PublicId)

	tests := []struct {
		name      string
		update    *kms.RootKey
		fieldMask []string
	}{
		{
			name: "private_id",
			update: func() *kms.RootKey {
				k := new.Clone().(*kms.RootKey)
				k.PrivateId = "o_thisIsNotAValidId"
				return k
			}(),
			fieldMask: []string{"PrivateId"},
		},
		{
			name: "create time",
			update: func() *kms.RootKey {
				k := new.Clone().(*kms.RootKey)
				k.CreateTime = &ts
				return k
			}(),
			fieldMask: []string{"CreateTime"},
		},
		{
			name: "scope_id",
			update: func() *kms.RootKey {
				k := new.Clone().(*kms.RootKey)
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
			err := rw.LookupById(context.Background(), orig)
			require.NoError(err)

			rowsUpdated, err := rw.Update(context.Background(), tt.update, tt.fieldMask, nil, db.WithSkipVetForWrite(true))
			require.Error(err)
			assert.Equal(0, rowsUpdated)

			after := new.Clone()
			err = rw.LookupById(context.Background(), after)
			require.NoError(err)

			assert.True(proto.Equal(orig.(*kms.RootKey), after.(*kms.RootKey)))
		})
	}
}

func TestDatabaseKey_ImmutableFields(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)

	ts := timestamp.Timestamp{Timestamp: &timestamppb.Timestamp{Seconds: 0, Nanos: 0}}

	wrapper := db.TestWrapper(t)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	db.TestDeleteWhere(t, conn, kms.AllocRootKey(), "1=1")
	db.TestDeleteWhere(t, conn, kms.AllocDatabaseKey(), "1=1")
	rk := kms.TestRootKey(t, conn, org.PublicId)
	new := kms.TestDatabaseKey(t, conn, rk.PrivateId)

	tests := []struct {
		name      string
		update    *kms.DatabaseKey
		fieldMask []string
	}{
		{
			name: "private_id",
			update: func() *kms.DatabaseKey {
				k := new.Clone().(*kms.DatabaseKey)
				k.PrivateId = "o_thisIsNotAValidId"
				return k
			}(),
			fieldMask: []string{"PrivateId"},
		},
		{
			name: "create time",
			update: func() *kms.DatabaseKey {
				k := new.Clone().(*kms.DatabaseKey)
				k.CreateTime = &ts
				return k
			}(),
			fieldMask: []string{"CreateTime"},
		},
		{
			name: "root_key_id",
			update: func() *kms.DatabaseKey {
				k := new.Clone().(*kms.DatabaseKey)
				k.RootKeyId = "o_thisIsNotAValidId"
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
			err := rw.LookupById(context.Background(), orig)
			require.NoError(err)

			rowsUpdated, err := rw.Update(context.Background(), tt.update, tt.fieldMask, nil, db.WithSkipVetForWrite(true))
			require.Error(err)
			assert.Equal(0, rowsUpdated)

			after := new.Clone()
			err = rw.LookupById(context.Background(), after)
			require.NoError(err)

			assert.True(proto.Equal(orig.(*kms.DatabaseKey), after.(*kms.DatabaseKey)))
		})
	}
}

func TestDatabaseKeyVersion_ImmutableFields(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	rw := db.New(conn)

	ts := timestamp.Timestamp{Timestamp: &timestamppb.Timestamp{Seconds: 0, Nanos: 0}}

	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	db.TestDeleteWhere(t, conn, kms.AllocRootKey(), "1=1")
	rk := kms.TestRootKey(t, conn, org.PublicId)
	_, rkvWrapper := kms.TestRootKeyVersion(t, conn, wrapper, rk.PrivateId)
	dk := kms.TestDatabaseKey(t, conn, rk.PrivateId)
	new := kms.TestDatabaseKeyVersion(t, conn, rkvWrapper, dk.PrivateId, []byte("database key"))

	tests := []struct {
		name      string
		update    *kms.DatabaseKeyVersion
		fieldMask []string
	}{
		{
			name: "private_id",
			update: func() *kms.DatabaseKeyVersion {
				k := new.Clone().(*kms.DatabaseKeyVersion)
				k.PrivateId = "o_thisIsNotAValidId"
				return k
			}(),
			fieldMask: []string{"PrivateId"},
		},
		{
			name: "create time",
			update: func() *kms.DatabaseKeyVersion {
				k := new.Clone().(*kms.DatabaseKeyVersion)
				k.CreateTime = &ts
				return k
			}(),
			fieldMask: []string{"CreateTime"},
		},
		{
			name: "database_key_id",
			update: func() *kms.DatabaseKeyVersion {
				k := new.Clone().(*kms.DatabaseKeyVersion)
				k.DatabaseKeyId = "o_thisIsNotAValidId"
				return k
			}(),
			fieldMask: []string{"RootKeyId"},
		},
		{
			name: "root_key_version_id",
			update: func() *kms.DatabaseKeyVersion {
				k := new.Clone().(*kms.DatabaseKeyVersion)
				k.RootKeyVersionId = "o_thisIsNotAValidId"
				return k
			}(),
			fieldMask: []string{"RootKeyId"},
		},
		{
			name: "version",
			update: func() *kms.DatabaseKeyVersion {
				k := new.Clone().(*kms.DatabaseKeyVersion)
				k.Version = uint32(22)
				return k
			}(),
			fieldMask: []string{"Version"},
		},
		{
			name: "key",
			update: func() *kms.DatabaseKeyVersion {
				k := new.Clone().(*kms.DatabaseKeyVersion)
				k.Key = []byte("updated key")
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
			err := rw.LookupById(context.Background(), orig)
			require.NoError(err)

			err = tt.update.Encrypt(context.Background(), wrapper)
			require.NoError(err)
			rowsUpdated, err := rw.Update(context.Background(), tt.update, tt.fieldMask, nil, db.WithSkipVetForWrite(true))
			require.Error(err)
			assert.Equal(0, rowsUpdated)

			after := new.Clone()
			err = rw.LookupById(context.Background(), after)
			require.NoError(err)

			assert.True(proto.Equal(orig.(*kms.DatabaseKeyVersion), after.(*kms.DatabaseKeyVersion)))
		})
	}
}

func TestOidcKey_ImmutableFields(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)

	ts := timestamp.Timestamp{Timestamp: &timestamppb.Timestamp{Seconds: 0, Nanos: 0}}

	wrapper := db.TestWrapper(t)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	db.TestDeleteWhere(t, conn, kms.AllocRootKey(), "1=1")
	db.TestDeleteWhere(t, conn, kms.AllocOidcKey(), "1=1")
	rk := kms.TestRootKey(t, conn, org.PublicId)
	new := kms.TestOidcKey(t, conn, rk.PrivateId)

	tests := []struct {
		name      string
		update    *kms.OidcKey
		fieldMask []string
	}{
		{
			name: "private_id",
			update: func() *kms.OidcKey {
				k := new.Clone().(*kms.OidcKey)
				k.PrivateId = "o_thisIsNotAValidId"
				return k
			}(),
			fieldMask: []string{"PrivateId"},
		},
		{
			name: "create time",
			update: func() *kms.OidcKey {
				k := new.Clone().(*kms.OidcKey)
				k.CreateTime = &ts
				return k
			}(),
			fieldMask: []string{"CreateTime"},
		},
		{
			name: "root_key_id",
			update: func() *kms.OidcKey {
				k := new.Clone().(*kms.OidcKey)
				k.RootKeyId = "o_thisIsNotAValidId"
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
			err := rw.LookupById(context.Background(), orig)
			require.NoError(err)

			rowsUpdated, err := rw.Update(context.Background(), tt.update, tt.fieldMask, nil, db.WithSkipVetForWrite(true))
			require.Error(err)
			assert.Equal(0, rowsUpdated)

			after := new.Clone()
			err = rw.LookupById(context.Background(), after)
			require.NoError(err)

			assert.True(proto.Equal(orig.(*kms.OidcKey), after.(*kms.OidcKey)))
		})
	}
}

func TestOidcKeyVersion_ImmutableFields(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	rw := db.New(conn)

	ts := timestamp.Timestamp{Timestamp: &timestamppb.Timestamp{Seconds: 0, Nanos: 0}}

	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	db.TestDeleteWhere(t, conn, kms.AllocRootKey(), "1=1")
	rk := kms.TestRootKey(t, conn, org.PublicId)
	_, rkvWrapper := kms.TestRootKeyVersion(t, conn, wrapper, rk.PrivateId)
	dk := kms.TestOidcKey(t, conn, rk.PrivateId)
	new := kms.TestOidcKeyVersion(t, conn, rkvWrapper, dk.PrivateId, []byte("oidc key"))

	tests := []struct {
		name      string
		update    *kms.OidcKeyVersion
		fieldMask []string
	}{
		{
			name: "private_id",
			update: func() *kms.OidcKeyVersion {
				k := new.Clone().(*kms.OidcKeyVersion)
				k.PrivateId = "o_thisIsNotAValidId"
				return k
			}(),
			fieldMask: []string{"PrivateId"},
		},
		{
			name: "create time",
			update: func() *kms.OidcKeyVersion {
				k := new.Clone().(*kms.OidcKeyVersion)
				k.CreateTime = &ts
				return k
			}(),
			fieldMask: []string{"CreateTime"},
		},
		{
			name: "oidc_key_id",
			update: func() *kms.OidcKeyVersion {
				k := new.Clone().(*kms.OidcKeyVersion)
				k.OidcKeyId = "o_thisIsNotAValidId"
				return k
			}(),
			fieldMask: []string{"RootKeyId"},
		},
		{
			name: "root_key_version_id",
			update: func() *kms.OidcKeyVersion {
				k := new.Clone().(*kms.OidcKeyVersion)
				k.RootKeyVersionId = "o_thisIsNotAValidId"
				return k
			}(),
			fieldMask: []string{"RootKeyId"},
		},
		{
			name: "version",
			update: func() *kms.OidcKeyVersion {
				k := new.Clone().(*kms.OidcKeyVersion)
				k.Version = uint32(22)
				return k
			}(),
			fieldMask: []string{"Version"},
		},
		{
			name: "key",
			update: func() *kms.OidcKeyVersion {
				k := new.Clone().(*kms.OidcKeyVersion)
				k.Key = []byte("updated key")
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
			err := rw.LookupById(context.Background(), orig)
			require.NoError(err)

			err = tt.update.Encrypt(context.Background(), wrapper)
			require.NoError(err)
			rowsUpdated, err := rw.Update(context.Background(), tt.update, tt.fieldMask, nil, db.WithSkipVetForWrite(true))
			require.Error(err)
			assert.Equal(0, rowsUpdated)

			after := new.Clone()
			err = rw.LookupById(context.Background(), after)
			require.NoError(err)

			assert.True(proto.Equal(orig.(*kms.OidcKeyVersion), after.(*kms.OidcKeyVersion)))
		})
	}
}

func TestAuditKey_ImmutableFields(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)

	ts := timestamp.Timestamp{Timestamp: &timestamppb.Timestamp{Seconds: 0, Nanos: 0}}

	wrapper := db.TestWrapper(t)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	db.TestDeleteWhere(t, conn, kms.AllocRootKey(), "1=1")
	db.TestDeleteWhere(t, conn, kms.AllocAuditKey(), "1=1")
	rk := kms.TestRootKey(t, conn, org.PublicId)
	new := kms.TestAuditKey(t, conn, rk.PrivateId)

	tests := []struct {
		name      string
		update    *kms.AuditKey
		fieldMask []string
	}{
		{
			name: "private_id",
			update: func() *kms.AuditKey {
				k := new.Clone().(*kms.AuditKey)
				k.PrivateId = "o_thisIsNotAValidId"
				return k
			}(),
			fieldMask: []string{"PrivateId"},
		},
		{
			name: "create time",
			update: func() *kms.AuditKey {
				k := new.Clone().(*kms.AuditKey)
				k.CreateTime = &ts
				return k
			}(),
			fieldMask: []string{"CreateTime"},
		},
		{
			name: "root_key_id",
			update: func() *kms.AuditKey {
				k := new.Clone().(*kms.AuditKey)
				k.RootKeyId = "o_thisIsNotAValidId"
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
			err := rw.LookupById(context.Background(), orig)
			require.NoError(err)

			rowsUpdated, err := rw.Update(context.Background(), tt.update, tt.fieldMask, nil, db.WithSkipVetForWrite(true))
			require.Error(err)
			assert.Equal(0, rowsUpdated)

			after := new.Clone()
			err = rw.LookupById(context.Background(), after)
			require.NoError(err)

			assert.True(proto.Equal(orig.(*kms.AuditKey), after.(*kms.AuditKey)))
		})
	}
}

func TestAuditKeyVersion_ImmutableFields(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	rw := db.New(conn)

	ts := timestamp.Timestamp{Timestamp: &timestamppb.Timestamp{Seconds: 0, Nanos: 0}}

	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	db.TestDeleteWhere(t, conn, kms.AllocRootKey(), "1=1")
	rk := kms.TestRootKey(t, conn, org.PublicId)
	_, rkvWrapper := kms.TestRootKeyVersion(t, conn, wrapper, rk.PrivateId)
	conn.Debug(true)
	dk := kms.TestAuditKey(t, conn, rk.PrivateId)
	new := kms.TestAuditKeyVersion(t, conn, rkvWrapper, dk.PrivateId, []byte("audit key"))

	tests := []struct {
		name      string
		update    *kms.AuditKeyVersion
		fieldMask []string
	}{
		{
			name: "private_id",
			update: func() *kms.AuditKeyVersion {
				k := new.Clone().(*kms.AuditKeyVersion)
				k.PrivateId = "o_thisIsNotAValidId"
				return k
			}(),
			fieldMask: []string{"PrivateId"},
		},
		{
			name: "create time",
			update: func() *kms.AuditKeyVersion {
				k := new.Clone().(*kms.AuditKeyVersion)
				k.CreateTime = &ts
				return k
			}(),
			fieldMask: []string{"CreateTime"},
		},
		{
			name: "audit_key_id",
			update: func() *kms.AuditKeyVersion {
				k := new.Clone().(*kms.AuditKeyVersion)
				k.AuditKeyId = "o_thisIsNotAValidId"
				return k
			}(),
			fieldMask: []string{"RootKeyId"},
		},
		{
			name: "root_key_version_id",
			update: func() *kms.AuditKeyVersion {
				k := new.Clone().(*kms.AuditKeyVersion)
				k.RootKeyVersionId = "o_thisIsNotAValidId"
				return k
			}(),
			fieldMask: []string{"RootKeyId"},
		},
		{
			name: "version",
			update: func() *kms.AuditKeyVersion {
				k := new.Clone().(*kms.AuditKeyVersion)
				k.Version = uint32(22)
				return k
			}(),
			fieldMask: []string{"Version"},
		},
		{
			name: "key",
			update: func() *kms.AuditKeyVersion {
				k := new.Clone().(*kms.AuditKeyVersion)
				k.Key = []byte("updated key")
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
			err := rw.LookupById(context.Background(), orig)
			require.NoError(err)

			err = tt.update.Encrypt(context.Background(), wrapper)
			require.NoError(err)
			rowsUpdated, err := rw.Update(context.Background(), tt.update, tt.fieldMask, nil, db.WithSkipVetForWrite(true))
			require.Error(err)
			assert.Equal(0, rowsUpdated)

			after := new.Clone()
			err = rw.LookupById(context.Background(), after)
			require.NoError(err)

			assert.True(proto.Equal(orig.(*kms.AuditKeyVersion), after.(*kms.AuditKeyVersion)))
		})
	}
}
