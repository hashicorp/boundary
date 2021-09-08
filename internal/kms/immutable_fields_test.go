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

// TODO (jimlambrt 8/2020) define tests for immutable fields in the remaining
// kms tables:
//	kms_oplog_key
//	kms_oplog_key_version
//	kms_session_key
//	kms_session_key_version

func TestRootKeyVersion_ImmutableFields(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	rw := db.New(conn)

	ts := timestamp.Timestamp{Timestamp: &timestamppb.Timestamp{Seconds: 0, Nanos: 0}}

	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	require.NoError(t, conn.Where("1=1").Delete(kms.AllocRootKey()).Error)
	require.NoError(t, conn.Where("1=1").Delete(kms.AllocRootKeyVersion()).Error)
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
	require.NoError(t, conn.Where("1=1").Delete(kms.AllocRootKey()).Error)
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
	require.NoError(t, conn.Where("1=1").Delete(kms.AllocRootKey()).Error)
	require.NoError(t, conn.Where("1=1").Delete(kms.AllocDatabaseKey()).Error)
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
	require.NoError(t, conn.Where("1=1").Delete(kms.AllocRootKey()).Error)
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

func TestOidcKeyVersion_ImmutableFields(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	rw := db.New(conn)

	ts := timestamp.Timestamp{Timestamp: &timestamppb.Timestamp{Seconds: 0, Nanos: 0}}

	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	require.NoError(t, conn.Where("1=1").Delete(kms.AllocRootKey()).Error)
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
