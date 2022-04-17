package kms_test

import (
	"context"
	"crypto/rand"
	"io"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/types/scope"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewRepository(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	type args struct {
		r db.Reader
		w db.Writer
	}
	tests := []struct {
		name          string
		args          args
		want          *kms.Repository
		wantErr       bool
		wantErrString string
	}{
		{
			name: "valid",
			args: args{
				r: rw,
				w: rw,
			},
			want: func() *kms.Repository {
				ret, err := kms.NewRepository(rw, rw)
				require.NoError(t, err)
				return ret
			}(),
			wantErr: false,
		},
		{
			name: "nil-writer",
			args: args{
				r: rw,
				w: nil,
			},
			want:          nil,
			wantErr:       true,
			wantErrString: "kms.NewRepository: nil writer: parameter violation: error #100",
		},
		{
			name: "nil-reader",
			args: args{
				r: nil,
				w: rw,
			},
			want:          nil,
			wantErr:       true,
			wantErrString: "kms.NewRepository: nil reader: parameter violation: error #100",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := kms.NewRepository(tt.args.r, tt.args.w)
			if tt.wantErr {
				require.Error(err)
				assert.Equal(tt.wantErrString, err.Error())
				return
			}
			require.NoError(err)
			assert.Equal(tt.want, got)
		})
	}
}

func TestCreateKeysTx(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	db.TestDeleteWhere(t, conn, func() interface{} { i := kms.AllocRootKey(); return &i }(), "1=1")

	type args struct {
		ctx          context.Context
		dbReader     db.Reader
		dbWriter     db.Writer
		rootWrapper  wrapping.Wrapper
		randomReader io.Reader
		scopeId      string
	}
	tests := []struct {
		name      string
		args      args
		wantErr   bool
		wantErrIs errors.Code
	}{
		{
			name: "valid",
			args: args{
				dbReader:     rw,
				dbWriter:     rw,
				rootWrapper:  wrapper,
				randomReader: rand.Reader,
				scopeId:      org.PublicId,
			},
		},
		{
			name: "valid-at-global",
			args: args{
				dbReader:     rw,
				dbWriter:     rw,
				rootWrapper:  wrapper,
				randomReader: rand.Reader,
				scopeId:      scope.Global.String(),
			},
		},
		{
			name: "nil-reader",
			args: args{
				dbReader:     nil,
				dbWriter:     rw,
				rootWrapper:  wrapper,
				randomReader: rand.Reader,
				scopeId:      org.PublicId,
			},
			wantErr:   true,
			wantErrIs: errors.InvalidParameter,
		},
		{
			name: "nil-writer",
			args: args{
				dbReader:     rw,
				dbWriter:     nil,
				rootWrapper:  wrapper,
				randomReader: rand.Reader,
				scopeId:      org.PublicId,
			},
			wantErr:   true,
			wantErrIs: errors.InvalidParameter,
		},
		{
			name: "nil-wrapper",
			args: args{
				dbReader:     rw,
				dbWriter:     rw,
				rootWrapper:  nil,
				randomReader: rand.Reader,
				scopeId:      org.PublicId,
			},
			wantErr:   true,
			wantErrIs: errors.InvalidParameter,
		},
		{
			name: "empty-scope",
			args: args{
				dbReader:     rw,
				dbWriter:     rw,
				rootWrapper:  wrapper,
				randomReader: rand.Reader,
				scopeId:      "",
			},
			wantErr:   true,
			wantErrIs: errors.InvalidParameter,
		},
		{
			name: "bad-scope",
			args: args{
				dbReader:     rw,
				dbWriter:     rw,
				rootWrapper:  wrapper,
				randomReader: rand.Reader,
				scopeId:      "o_thisIsAnInvalidScopeId",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			keys, err := kms.DeprecatedCreateKeysTx(tt.args.ctx, tt.args.dbReader, tt.args.dbWriter, tt.args.rootWrapper, tt.args.randomReader, tt.args.scopeId)
			if tt.wantErr {
				require.Error(err)
				assert.Truef(errors.Match(errors.T(tt.wantErrIs), err), "unexpected error: %s", err.Error())
				return
			}
			require.NoError(err)
			rk := kms.AllocRootKey()
			rk.PrivateId = keys[kms.KeyTypeRootKey].GetPrivateId()
			err = rw.LookupById(context.Background(), &rk)
			require.NoError(err)
			assert.Equal(rk.ScopeId, tt.args.scopeId)

			rkv := kms.AllocRootKeyVersion()
			rkv.PrivateId = keys[kms.KeyTypeRootKeyVersion].GetPrivateId()
			err = rw.LookupById(context.Background(), &rkv)
			require.NoError(err)
			assert.Equal(rkv.RootKeyId, rk.PrivateId)

			dk := kms.AllocDatabaseKey()
			dk.PrivateId = keys[kms.KeyTypeDatabaseKey].GetPrivateId()
			err = rw.LookupById(context.Background(), &dk)
			require.NoError(err)
			assert.Equal(rk.PrivateId, dk.RootKeyId)

			dkv := kms.AllocDatabaseKeyVersion()
			dkv.PrivateId = keys[kms.KeyTypeDatabaseKeyVersion].GetPrivateId()
			err = rw.LookupById(context.Background(), &dkv)
			require.NoError(err)
			assert.Equal(dk.PrivateId, dkv.DatabaseKeyId)
			assert.Equal(rkv.PrivateId, dkv.RootKeyVersionId)

			opk := kms.AllocOplogKey()
			opk.PrivateId = keys[kms.KeyTypeOplogKey].GetPrivateId()
			err = rw.LookupById(context.Background(), &opk)
			require.NoError(err)
			assert.Equal(rk.PrivateId, opk.RootKeyId)

			opkv := kms.AllocOplogKeyVersion()
			opkv.PrivateId = keys[kms.KeyTypeOplogKeyVersion].GetPrivateId()
			err = rw.LookupById(context.Background(), &opkv)
			require.NoError(err)
			assert.Equal(opk.PrivateId, opkv.OplogKeyId)
			assert.Equal(rkv.PrivateId, opkv.RootKeyVersionId)

			sk := kms.AllocSessionKey()
			sk.PrivateId = keys[kms.KeyTypeSessionKey].GetPrivateId()
			err = rw.LookupById(context.Background(), &sk)
			require.NoError(err)
			assert.Equal(rk.PrivateId, sk.RootKeyId)

			skv := kms.AllocSessionKeyVersion()
			skv.PrivateId = keys[kms.KeyTypeSessionKeyVersion].GetPrivateId()
			err = rw.LookupById(context.Background(), &skv)
			require.NoError(err)
			assert.Equal(sk.PrivateId, skv.SessionKeyId)
			assert.Equal(rkv.PrivateId, skv.RootKeyVersionId)

			tk := kms.AllocTokenKey()
			tk.PrivateId = keys[kms.KeyTypeTokenKey].GetPrivateId()
			err = rw.LookupById(context.Background(), &tk)
			require.NoError(err)
			assert.Equal(rk.PrivateId, tk.RootKeyId)

			tkv := kms.AllocTokenKeyVersion()
			tkv.PrivateId = keys[kms.KeyTypeTokenKeyVersion].GetPrivateId()
			err = rw.LookupById(context.Background(), &tkv)
			require.NoError(err)
			assert.Equal(tk.PrivateId, tkv.TokenKeyId)
			assert.Equal(rkv.PrivateId, tkv.RootKeyVersionId)

			oidcK := kms.AllocOidcKey()
			oidcK.PrivateId = keys[kms.KeyTypeOidcKey].GetPrivateId()
			err = rw.LookupById(context.Background(), &oidcK)
			require.NoError(err)
			assert.Equal(rk.PrivateId, oidcK.RootKeyId)

			oidcKv := kms.AllocOidcKeyVersion()
			oidcKv.PrivateId = keys[kms.KeyTypeOidcKeyVersion].GetPrivateId()
			err = rw.LookupById(context.Background(), &oidcKv)
			require.NoError(err)
			assert.Equal(oidcK.PrivateId, oidcKv.OidcKeyId)
			assert.Equal(rkv.PrivateId, oidcKv.RootKeyVersionId)

			if tt.args.scopeId == scope.Global.String() {
				auditK := kms.AllocAuditKey()
				auditK.PrivateId = keys[kms.KeyTypeAuditKey].GetPrivateId()
				err = rw.LookupById(context.Background(), &auditK)
				require.NoError(err)
				assert.Equal(rk.PrivateId, auditK.RootKeyId)

				auditKv := kms.AllocAuditKeyVersion()
				auditKv.PrivateId = keys[kms.KeyTypeAuditKeyVersion].GetPrivateId()
				err = rw.LookupById(context.Background(), &auditKv)
				require.NoError(err)
				assert.Equal(auditK.PrivateId, auditKv.AuditKeyId)
				assert.Equal(rkv.PrivateId, auditKv.RootKeyVersionId)
			}
		})
	}
}
