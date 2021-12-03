package plugin

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	hostplg "github.com/hashicorp/boundary/internal/plugin/host"
	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/stretchr/testify/assert"
	assertpkg "github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	requirepkg "github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestNewRefreshHostCatalogPersistedJob(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)

	plg := hostplg.TestPlugin(t, conn, "lookup")
	plgm := map[string]plgpb.HostPluginServiceClient{
		plg.GetPublicId(): NewWrappingPluginClient(&TestPluginServer{}),
	}

	type args struct {
		r    db.Reader
		w    db.Writer
		kms  *kms.Kms
		plgm map[string]plgpb.HostPluginServiceClient
	}
	tests := []struct {
		name        string
		args        args
		options     []Option
		wantLimit   int
		wantErr     bool
		wantErrCode errors.Code
	}{
		{
			name: "nil reader",
			args: args{
				w:    rw,
				kms:  kmsCache,
				plgm: plgm,
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name: "nil writer",
			args: args{
				r:    rw,
				kms:  kmsCache,
				plgm: plgm,
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name: "nil kms",
			args: args{
				r:    rw,
				w:    rw,
				plgm: plgm,
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name: "nil plgm",
			args: args{
				r:   rw,
				w:   rw,
				kms: kmsCache,
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name: "valid-no-options",
			args: args{
				r:    rw,
				w:    rw,
				kms:  kmsCache,
				plgm: plgm,
			},
			wantLimit: db.DefaultLimit,
		},
		{
			name: "valid-with-limit",
			args: args{
				r:    rw,
				w:    rw,
				kms:  kmsCache,
				plgm: plgm,
			},
			options:   []Option{WithLimit(100)},
			wantLimit: 100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assertpkg.New(t), requirepkg.New(t)

			got, err := newRefreshHostCatalogPersistedJob(ctx, tt.args.r, tt.args.w, tt.args.kms, tt.args.plgm, tt.options...)
			if tt.wantErr {
				require.Error(err)
				assert.Nil(got)
				assert.Truef(errors.Match(errors.T(tt.wantErrCode), err), "Unexpected error %s", err)
				return
			}
			require.NoError(err)
			require.NotNil(got)
			assert.Equal(tt.args.r, got.reader)
			assert.Equal(tt.args.w, got.writer)
			assert.Equal(tt.args.kms, got.kms)
			assert.Equal(tt.wantLimit, got.limit)
		})
	}
}

func TestRefreshHostCatalogPersistedJob_Run(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)

	plgServer1 := &TestPluginServer{}
	plgServer2 := &TestPluginServer{}
	plg1 := hostplg.TestPlugin(t, conn, "plg1")
	plg2 := hostplg.TestPlugin(t, conn, "plg2")
	plgm := map[string]plgpb.HostPluginServiceClient{
		plg1.GetPublicId(): NewWrappingPluginClient(plgServer1),
		plg2.GetPublicId(): NewWrappingPluginClient(plgServer2),
	}

	job, err := newRefreshHostCatalogPersistedJob(ctx, rw, rw, kmsCache, plgm)
	require.NoError(t, err)
	require.NoError(t, err)

	err = job.Run(context.Background())
	require.NoError(t, err)
	// No sets should have been synced.
	require.Equal(t, 0, job.numProcessed)

	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

	// Define a function for setting up host catalogs.
	setupHostCatalog := func(t *testing.T, ctx context.Context, pluginId string, secrets map[string]interface{}) *HostCatalog {
		t.Helper()
		require := require.New(t)

		cat := TestCatalog(t, conn, prj.PublicId, pluginId)
		scopeWrapper, err := kmsCache.GetWrapper(ctx, cat.GetScopeId(), kms.KeyPurposeDatabase)
		require.NoError(err)
		cat.Secrets = mustStruct(secrets)
		require.NoError(cat.hmacSecrets(ctx, scopeWrapper))
		cSecret, err := newHostCatalogSecret(ctx, cat.GetPublicId(), cat.Secrets)
		require.NoError(err)
		require.NoError(cSecret.encrypt(ctx, scopeWrapper))
		cSecretQ, cSecretV := cSecret.upsertQuery()
		secretsUpdated, err := rw.Exec(ctx, cSecretQ, cSecretV)
		require.NoError(err)
		require.Equal(1, secretsUpdated)

		t.Cleanup(func() {
			t.Helper()
			assert := assert.New(t)
			n, err := rw.Delete(ctx, cat)
			assert.NoError(err)
			assert.Equal(1, n)
		})

		return cat
	}

	type refreshHostCatalogPersistedFn func(context.Context, *plgpb.RefreshHostCatalogPersistedRequest) (*plgpb.RefreshHostCatalogPersistedResponse, error)
	makeRefreshPersistedFn := func(gotReq **plgpb.RefreshHostCatalogPersistedRequest, wantResponse *plgpb.RefreshHostCatalogPersistedResponse) refreshHostCatalogPersistedFn {
		return func(_ context.Context, req *plgpb.RefreshHostCatalogPersistedRequest) (*plgpb.RefreshHostCatalogPersistedResponse, error) {
			*gotReq = req
			return wantResponse, nil
		}
	}

	var gotReq1 *plgpb.RefreshHostCatalogPersistedRequest
	wantReq1 := map[string]interface{}{"foo": "bar"}
	wantSecrets1 := map[string]interface{}{"baz": "qux"}
	wantResponse1 := &plgpb.RefreshHostCatalogPersistedResponse{
		Persisted: &plgpb.HostCatalogPersisted{
			Secrets: mustStruct(wantSecrets1),
		},
	}
	var gotReq2 *plgpb.RefreshHostCatalogPersistedRequest
	wantReq2 := map[string]interface{}{"one": "two"}
	wantSecrets2 := map[string]interface{}{"three": "four"}
	wantResponse2 := &plgpb.RefreshHostCatalogPersistedResponse{
		Persisted: &plgpb.HostCatalogPersisted{
			Secrets: mustStruct(wantSecrets2),
		},
	}
	plgServer1.RefreshHostCatalogPersistedFn = makeRefreshPersistedFn(&gotReq1, wantResponse1)
	plgServer2.RefreshHostCatalogPersistedFn = makeRefreshPersistedFn(&gotReq2, wantResponse2)

	cat1 := setupHostCatalog(t, ctx, plg1.GetPublicId(), wantReq1)
	cat2 := setupHostCatalog(t, ctx, plg2.GetPublicId(), wantReq2)

	err = job.Run(context.Background())
	require.NoError(t, err)
	require.Equal(t, 2, job.numProcessed)

	// Assert received secrets
	require.Empty(t, cmp.Diff(mustStruct(wantReq1), gotReq1.Persisted.Secrets, protocmp.Transform()))
	require.Empty(t, cmp.Diff(mustStruct(wantReq2), gotReq2.Persisted.Secrets, protocmp.Transform()))

	// Now check to make sure that the host catalogs have had their
	// secrets updated.
	checkSecrets := func(t *testing.T, ctx context.Context, cat *HostCatalog, want map[string]interface{}) {
		t.Helper()
		require := require.New(t)

		cSecret := allocHostCatalogSecret()
		err := rw.LookupWhere(ctx, &cSecret, "catalog_id=?", cat.GetPublicId())
		require.NoError(err)
		require.Empty(cSecret.Secret)
		require.NotEmpty(cSecret.CtSecret)

		dbWrapper, err := kmsCache.GetWrapper(ctx, cat.GetScopeId(), kms.KeyPurposeDatabase)
		require.NoError(err)
		require.NoError(cSecret.decrypt(ctx, dbWrapper))

		st := &structpb.Struct{}
		require.NoError(proto.Unmarshal(cSecret.Secret, st))
		require.Empty(cmp.Diff(mustStruct(want), st, protocmp.Transform()))
	}

	checkSecrets(t, ctx, cat1, wantSecrets1)
	checkSecrets(t, ctx, cat2, wantSecrets2)
}
