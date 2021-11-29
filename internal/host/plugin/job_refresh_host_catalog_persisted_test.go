package plugin

import (
	"context"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	hostplg "github.com/hashicorp/boundary/internal/plugin/host"
	"github.com/hashicorp/boundary/internal/scheduler"
	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/stretchr/testify/assert"
	assertpkg "github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	requirepkg "github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// assert the interface
var _ = scheduler.Job(new(RefreshHostCatalogPersistedJob))

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
	require.NotNil(t, job)

	require.NoError(t, job.Run(context.Background()))
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
		cSecret, err := newHostCatalogSecret(ctx, cat.GetPublicId(), nil, cat.Secrets)
		require.NoError(err)
		require.NoError(cSecret.encrypt(ctx, scopeWrapper))
		err = rw.Create(ctx, cSecret)
		require.NoError(err)

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

	// We set this up here, but we don't use it just yet (this is for the final tests where we validate things were updated)
	ttlStep := uint32(5)
	var gotReq1 *plgpb.RefreshHostCatalogPersistedRequest
	wantReq1 := map[string]interface{}{"foo": "bar"}
	reqTtl1 := ttlStep
	respTtl1 := reqTtl1 + ttlStep
	wantSecrets1 := map[string]interface{}{"baz": "qux"}
	wantResponse1 := &plgpb.RefreshHostCatalogPersistedResponse{
		Persisted: &plgpb.HostCatalogPersisted{
			Secrets:    mustStruct(wantSecrets1),
			TtlSeconds: wrapperspb.UInt32(respTtl1),
		},
	}
	var gotReq2 *plgpb.RefreshHostCatalogPersistedRequest
	wantReq2 := map[string]interface{}{"one": "two"}
	reqTtl2 := respTtl1
	respTtl2 := reqTtl2 + ttlStep
	wantSecrets2 := map[string]interface{}{"three": "four"}
	wantResponse2 := &plgpb.RefreshHostCatalogPersistedResponse{
		Persisted: &plgpb.HostCatalogPersisted{
			Secrets:    mustStruct(wantSecrets2),
			TtlSeconds: wrapperspb.UInt32(respTtl2),
		},
	}
	plgServer1.RefreshHostCatalogPersistedFn = makeRefreshPersistedFn(&gotReq1, wantResponse1)
	plgServer2.RefreshHostCatalogPersistedFn = makeRefreshPersistedFn(&gotReq2, wantResponse2)

	cat1 := setupHostCatalog(t, ctx, plg1.GetPublicId(), wantReq1)
	cat2 := setupHostCatalog(t, ctx, plg2.GetPublicId(), wantReq2)

	// Run the job again. Note that we have not set a refresh time, so no jobs should have run again.
	require.NoError(t, job.Run(context.Background()))
	require.Equal(t, 0, job.numProcessed)

	// We define a check function here and use it to validate that the secrets
	// remain unchanged. Also check that request was never sent.
	checkSecrets := func(t *testing.T, ctx context.Context, cat *HostCatalog, wantRefreshAtTime *timestamp.Timestamp, want map[string]interface{}) {
		t.Helper()
		require := require.New(t)

		cSecret := allocHostCatalogSecret()
		require.NoError(rw.LookupWhere(ctx, &cSecret, "catalog_id=?", cat.GetPublicId()))
		require.Empty(cSecret.Secret)
		require.NotEmpty(cSecret.CtSecret)
		if wantRefreshAtTime != nil {
			require.Equal(wantRefreshAtTime.AsTime().Truncate(time.Second), cSecret.RefreshAtTime.AsTime().Truncate(time.Second))
		} else {
			require.Nil(cSecret.RefreshAtTime)
		}

		dbWrapper, err := kmsCache.GetWrapper(ctx, cat.GetScopeId(), kms.KeyPurposeDatabase)
		require.NoError(err)
		require.NoError(cSecret.decrypt(ctx, dbWrapper))

		st := &structpb.Struct{}
		require.NoError(proto.Unmarshal(cSecret.Secret, st))
		require.Empty(cmp.Diff(mustStruct(want), st, protocmp.Transform()))
	}

	require.Nil(t, gotReq1)
	require.Nil(t, gotReq2)
	checkSecrets(t, ctx, cat1, nil, wantReq1)
	checkSecrets(t, ctx, cat2, nil, wantReq2)

	// Now let's set our TTLs.
	updateTtl := func(t *testing.T, ctx context.Context, cat *HostCatalog, ttl *wrapperspb.UInt32Value) {
		t.Helper()
		require := require.New(t)

		cSecret := allocHostCatalogSecret()
		require.NoError(rw.LookupWhere(ctx, &cSecret, "catalog_id=?", cat.GetPublicId()))
		cSecret.RefreshAtTime = timestamp.New(time.Now().UTC().Add(time.Second * time.Duration(ttl.GetValue())))
		n, err := rw.Update(ctx, cSecret, []string{"RefreshAtTime"}, []string{})
		require.NoError(err)
		require.Equal(n, 1)
	}

	// Compute some wanted RefreshAtTime values to align with what is set when we
	// set TTLs in the next step
	wantReq1RefreshAtTime := timestamp.New(time.Now().UTC().Add(time.Second * time.Duration(reqTtl1)))
	wantReq2RefreshAtTime := timestamp.New(time.Now().UTC().Add(time.Second * time.Duration(reqTtl2)))

	// Update
	updateTtl(t, ctx, cat1, wrapperspb.UInt32(reqTtl1))
	updateTtl(t, ctx, cat2, wrapperspb.UInt32(reqTtl2))
	// This check is just to assert that the ttl was set. These will get updated,
	// so we want to assert them here to their proper values.
	checkSecrets(t, ctx, cat1, wantReq1RefreshAtTime, wantReq1)
	checkSecrets(t, ctx, cat2, wantReq2RefreshAtTime, wantReq2)

	// Wait the step length and then run the job. Only one job should have run.
	time.Sleep(time.Second * time.Duration(ttlStep))

	// Compute another wanted RefreshAtTime for the first catalog before running the job to synchronize.
	wantResp1RefreshAtTime := timestamp.New(time.Now().UTC().Add(time.Second * time.Duration(respTtl1)))

	// Run job, only 1 job should have ran
	require.NoError(t, job.Run(context.Background()))
	require.Equal(t, 1, job.numProcessed)

	// Assert received secret on the first job, ensure second is still nil.
	require.Empty(t, cmp.Diff(mustStruct(wantReq1), gotReq1.Persisted.Secrets, protocmp.Transform()))
	require.Equal(t, wantReq1RefreshAtTime.AsTime().Truncate(time.Second), gotReq1.Persisted.RefreshAtTime.AsTime().Truncate(time.Second))
	require.Nil(t, gotReq1.Persisted.TtlSeconds)
	require.Nil(t, gotReq2)

	// Check state - updated secrets and TTL on 1st catalog, no change on second.
	checkSecrets(t, ctx, cat1, wantResp1RefreshAtTime, wantSecrets1)
	checkSecrets(t, ctx, cat2, wantReq2RefreshAtTime, wantReq2)

	// Repeat sleep/run cycle. Again, only one job should have been run. Before
	// we do this, reset the state of the received requests.
	gotReq1 = nil
	gotReq2 = nil
	time.Sleep(time.Second * time.Duration(ttlStep))

	// Compute wanted RefreshAtTime for second catalog before next job run
	wantResp2RefreshAtTime := timestamp.New(time.Now().UTC().Add(time.Second * time.Duration(respTtl2)))

	// Run job again, only one job should have ran
	require.NoError(t, job.Run(context.Background()))
	require.Equal(t, 1, job.numProcessed)

	// Assert requests the other way around now.
	require.Nil(t, gotReq1)
	require.Equal(t, wantReq2RefreshAtTime.AsTime().Truncate(time.Second), gotReq2.Persisted.RefreshAtTime.AsTime().Truncate(time.Second))
	require.Nil(t, gotReq2.Persisted.TtlSeconds)

	// Assert secrets again, this time with the second catalog's refresh time
	// updated as well. First catalog should remain as-is.
	checkSecrets(t, ctx, cat1, wantResp1RefreshAtTime, wantSecrets1)
	checkSecrets(t, ctx, cat2, wantResp2RefreshAtTime, wantSecrets2)
}

func TestRefreshHostCatalogPersistedJob_NextRunIn(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)

	plgServer := &TestPluginServer{}
	plg := hostplg.TestPlugin(t, conn, "plg1")
	plgm := map[string]plgpb.HostPluginServiceClient{
		plg.GetPublicId(): NewWrappingPluginClient(plgServer),
	}

	job, err := newRefreshHostCatalogPersistedJob(ctx, rw, rw, kmsCache, plgm)
	require.NoError(t, err)
	require.NotNil(t, job)

	// Without any catalogs, next run time should be 10 mins
	nextRunDuration, err := job.NextRunIn()
	require.NoError(t, err)
	require.Equal(t, refreshHostCatalogPersistedJobInterval, nextRunDuration)

	// Define a function for setting up host catalogs.
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	setupCatalog := func(t *testing.T, ctx context.Context, ttl uint32) (*HostCatalog, *HostCatalogSecret) {
		t.Helper()
		require := require.New(t)

		cat := TestCatalog(t, conn, prj.GetPublicId(), plg.GetPublicId())
		scopeWrapper, err := kmsCache.GetWrapper(ctx, cat.GetScopeId(), kms.KeyPurposeDatabase)
		require.NoError(err)
		cat.Secrets = mustStruct(map[string]interface{}{"foo": "bar"})
		require.NoError(cat.hmacSecrets(ctx, scopeWrapper))
		cSecret, err := newHostCatalogSecret(ctx, cat.GetPublicId(), wrapperspb.UInt32(ttl), cat.Secrets)
		require.NoError(err)
		require.NoError(cSecret.encrypt(ctx, scopeWrapper))
		err = rw.Create(ctx, cSecret)
		require.NoError(err)
		return cat, cSecret
	}

	cat1, secret1 := setupCatalog(t, ctx, 0)
	cat2, secret2 := setupCatalog(t, ctx, 10)

	// Run next run in, secret1 should be the next run time
	nextRunDuration, err = job.NextRunIn()
	require.NoError(t, err)
	require.Equal(t, time.Until(secret1.RefreshAtTime.AsTime()).Truncate(time.Second), nextRunDuration.Truncate(time.Second))

	// Now swap the stamps around, re-run, and check again, second one
	// should be the next run time now.
	secret2.RefreshAtTime = timestamp.New(time.Now().UTC())
	secret1.RefreshAtTime = timestamp.New(time.Now().UTC().Add(time.Second * 10))
	n, err := rw.Update(ctx, secret1, []string{"RefreshAtTime"}, []string{})
	require.NoError(t, err)
	require.Equal(t, 1, n)
	n, err = rw.Update(ctx, secret2, []string{"RefreshAtTime"}, []string{})
	require.NoError(t, err)
	require.Equal(t, 1, n)

	// Next run in should now be the same as secret2
	nextRunDuration, err = job.NextRunIn()
	require.NoError(t, err)
	require.Equal(t, time.Until(secret2.RefreshAtTime.AsTime()).Truncate(time.Second), nextRunDuration.Truncate(time.Second))

	// Delete catalogs, and then try again, run time should be 10 mins
	// again
	n, err = rw.Delete(ctx, cat1)
	require.NoError(t, err)
	require.Equal(t, 1, n)
	n, err = rw.Delete(ctx, cat2)
	require.NoError(t, err)
	require.Equal(t, 1, n)
}
