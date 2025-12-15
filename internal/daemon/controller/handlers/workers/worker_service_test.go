// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package workers

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/downstream"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/server"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/scopes"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/workers"
	"github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/hashicorp/go-secure-stdlib/strutil"
	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/rotation"
	"github.com/hashicorp/nodeenrollment/storage/file"
	"github.com/hashicorp/nodeenrollment/types"
	"github.com/mr-tron/base58"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/protobuf/field_mask"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var testAuthorizedActions = []string{"no-op", "read", "update", "delete", "add-worker-tags", "set-worker-tags", "remove-worker-tags"}

func structListValue(t *testing.T, ss ...string) *structpb.ListValue {
	t.Helper()
	var val []any
	for _, s := range ss {
		val = append(val, s)
	}
	lv, err := structpb.NewList(val)
	require.NoError(t, err)
	return lv
}

func equalTags(t *testing.T, expected map[string]*structpb.ListValue, actual map[string]*structpb.ListValue) bool {
	t.Helper()
	if len(expected) != len(actual) {
		return false
	}
	for eK, eValList := range expected {
		found := false
		for k, valList := range actual {
			if eK == k && eValList.String() == valList.String() {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func TestGet(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrap)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	rw := db.New(conn)
	kms := kms.TestKms(t, conn, wrap)
	repo, err := server.NewRepository(ctx, rw, rw, kms)
	require.NoError(t, err)
	repoFn := func() (*server.Repository, error) {
		return repo, nil
	}
	oldDownstramFn := downstreamWorkers
	t.Cleanup(func() {
		downstreamWorkers = oldDownstramFn
	})
	connectedDownstreams := []string{"first", "second", "third"}
	downstreamWorkers = func(_ context.Context, id string, _ downstream.Graph) []string {
		return connectedDownstreams
	}

	workerAuthRepo, err := server.NewRepositoryStorage(ctx, rw, rw, kms)
	require.NoError(t, err)
	workerAuthRepoFn := func() (*server.WorkerAuthRepositoryStorage, error) {
		return workerAuthRepo, nil
	}

	deprecatedKmsWorker := server.TestKmsWorker(t, conn, wrap,
		server.WithName("test deprecated kms worker names"),
		server.WithDescription("test deprecated kms worker description"),
		server.WithAddress("test deprecated kms worker address"),
		server.WithWorkerTags(&server.Tag{Key: "key", Value: "val"}))

	deprecatedKmsAuthzActions := make([]string, len(testAuthorizedActions))
	copy(deprecatedKmsAuthzActions, testAuthorizedActions)

	wantDeprecatedKmsWorker := &pb.Worker{
		Id:                    deprecatedKmsWorker.GetPublicId(),
		ScopeId:               deprecatedKmsWorker.GetScopeId(),
		Scope:                 &scopes.ScopeInfo{Id: deprecatedKmsWorker.GetScopeId(), Type: scope.Global.String(), Name: scope.Global.String(), Description: "Global Scope"},
		CreatedTime:           deprecatedKmsWorker.CreateTime.GetTimestamp(),
		UpdatedTime:           deprecatedKmsWorker.UpdateTime.GetTimestamp(),
		Version:               deprecatedKmsWorker.GetVersion(),
		Name:                  wrapperspb.String(deprecatedKmsWorker.GetName()),
		Description:           wrapperspb.String(deprecatedKmsWorker.GetDescription()),
		Address:               deprecatedKmsWorker.GetAddress(),
		ActiveConnectionCount: &wrapperspb.UInt32Value{Value: 0},
		AuthorizedActions:     strutil.StrListDelete(deprecatedKmsAuthzActions, action.Update.String()),
		LastStatusTime:        deprecatedKmsWorker.GetLastStatusTime().GetTimestamp(),
		ReleaseVersion:        deprecatedKmsWorker.ReleaseVersion,
		CanonicalTags: map[string]*structpb.ListValue{
			"key": structListValue(t, "val"),
		},
		ConfigTags: map[string]*structpb.ListValue{
			"key": structListValue(t, "val"),
		},
		Type:                               KmsWorkerType,
		DirectlyConnectedDownstreamWorkers: connectedDownstreams,
		LocalStorageState:                  server.UnknownLocalStorageState.String(),
	}

	var pkiWorkerKeyId string
	pkiWorker := server.TestPkiWorker(t, conn, wrap,
		server.WithName("test pki worker names"),
		server.WithDescription("test pki worker description"),
		server.WithTestPkiWorkerAuthorizedKeyId(&pkiWorkerKeyId))
	// Add config tags to the created worker
	pkiWorker, err = server.TestUpsertAndReturnWorker(context.Background(), t,
		server.NewWorker(pkiWorker.GetScopeId(),
			server.WithAddress("test pki worker address"),
			server.WithLocalStorageState(server.AvailableLocalStorageState.String()),
			server.WithWorkerTags(&server.Tag{
				Key:   "config",
				Value: "test",
			})),
		repo,
		server.WithUpdateTags(true),
		server.WithPublicId(pkiWorker.GetPublicId()),
		server.WithKeyId(pkiWorkerKeyId),
	)
	require.NoError(t, err)

	wantPkiWorker := &pb.Worker{
		Id:                    pkiWorker.GetPublicId(),
		ScopeId:               pkiWorker.GetScopeId(),
		Scope:                 &scopes.ScopeInfo{Id: pkiWorker.GetScopeId(), Type: scope.Global.String(), Name: scope.Global.String(), Description: "Global Scope"},
		CreatedTime:           pkiWorker.CreateTime.GetTimestamp(),
		UpdatedTime:           pkiWorker.UpdateTime.GetTimestamp(),
		Version:               pkiWorker.GetVersion(),
		Name:                  wrapperspb.String(pkiWorker.GetName()),
		Description:           wrapperspb.String(pkiWorker.GetDescription()),
		Address:               pkiWorker.GetAddress(),
		AuthorizedActions:     testAuthorizedActions,
		ActiveConnectionCount: &wrapperspb.UInt32Value{Value: 0},
		LastStatusTime:        pkiWorker.GetLastStatusTime().GetTimestamp(),
		ReleaseVersion:        pkiWorker.ReleaseVersion,
		CanonicalTags: map[string]*structpb.ListValue{
			"config": structListValue(t, "test"),
		},
		ConfigTags: map[string]*structpb.ListValue{
			"config": structListValue(t, "test"),
		},
		Type:                               PkiWorkerType,
		DirectlyConnectedDownstreamWorkers: connectedDownstreams,
		LocalStorageState:                  server.AvailableLocalStorageState.String(),
	}

	var managedPkiWorkerKeyId string
	managedPkiWorkerName := "test managed pki worker name"
	managedPkiWorker := server.TestPkiWorker(t, conn, wrap,
		server.WithName("test managed pki worker name"),
		server.WithDescription("test managed pki worker description"),
		server.WithTestPkiWorkerAuthorizedKeyId(&managedPkiWorkerKeyId),
		// Passing this function for the ID will allow us to trick it into
		// considering it a KMS-authed worker, so we can verify that both update
		// and delete are removed
		server.WithNewIdFunc(func(context.Context) (string, error) {
			return server.NewWorkerIdFromScopeAndName(ctx, scope.Global.String(), managedPkiWorkerName)
		}),
	)

	// Add config tags to the created worker
	managedPkiWorker, err = server.TestUpsertAndReturnWorker(context.Background(), t,
		server.NewWorker(managedPkiWorker.GetScopeId(),
			server.WithAddress("test managed pki worker address"),
			server.WithLocalStorageState(server.AvailableLocalStorageState.String()),
			server.WithWorkerTags(&server.Tag{
				Key:   server.ManagedWorkerTag,
				Value: "true",
			})),
		repo,
		server.WithUpdateTags(true),
		server.WithPublicId(managedPkiWorker.GetPublicId()),
		server.WithKeyId(managedPkiWorkerKeyId))
	require.NoError(t, err)

	managedPkiAuthzActions := make([]string, len(testAuthorizedActions))
	copy(managedPkiAuthzActions, testAuthorizedActions)
	managedPkiAuthzActions = strutil.StrListDelete(managedPkiAuthzActions, action.Update.String())
	managedPkiAuthzActions = strutil.StrListDelete(managedPkiAuthzActions, action.Delete.String())

	wantManagedPkiWorker := &pb.Worker{
		Id:                    managedPkiWorker.GetPublicId(),
		ScopeId:               managedPkiWorker.GetScopeId(),
		Scope:                 &scopes.ScopeInfo{Id: managedPkiWorker.GetScopeId(), Type: scope.Global.String(), Name: scope.Global.String(), Description: "Global Scope"},
		CreatedTime:           managedPkiWorker.CreateTime.GetTimestamp(),
		UpdatedTime:           managedPkiWorker.UpdateTime.GetTimestamp(),
		Version:               managedPkiWorker.GetVersion(),
		Name:                  wrapperspb.String(managedPkiWorker.GetName()),
		Description:           wrapperspb.String(managedPkiWorker.GetDescription()),
		Address:               managedPkiWorker.GetAddress(),
		AuthorizedActions:     managedPkiAuthzActions,
		ActiveConnectionCount: &wrapperspb.UInt32Value{Value: 0},
		LastStatusTime:        managedPkiWorker.GetLastStatusTime().GetTimestamp(),
		ReleaseVersion:        managedPkiWorker.ReleaseVersion,
		CanonicalTags: map[string]*structpb.ListValue{
			server.ManagedWorkerTag: structListValue(t, "true"),
		},
		ConfigTags: map[string]*structpb.ListValue{
			server.ManagedWorkerTag: structListValue(t, "true"),
		},
		Type:                               PkiWorkerType,
		DirectlyConnectedDownstreamWorkers: connectedDownstreams,
		LocalStorageState:                  server.AvailableLocalStorageState.String(),
	}

	cases := []struct {
		name    string
		scopeId string
		req     *pbs.GetWorkerRequest
		res     *pbs.GetWorkerResponse
		err     error
	}{
		{
			name:    "Get an Existing Deprecated KMS Worker",
			scopeId: deprecatedKmsWorker.GetScopeId(),
			req:     &pbs.GetWorkerRequest{Id: deprecatedKmsWorker.GetPublicId()},
			res:     &pbs.GetWorkerResponse{Item: wantDeprecatedKmsWorker},
		},
		{
			name:    "Get an Existing PKI Worker",
			scopeId: pkiWorker.GetScopeId(),
			req:     &pbs.GetWorkerRequest{Id: pkiWorker.GetPublicId()},
			res:     &pbs.GetWorkerResponse{Item: wantPkiWorker},
		},
		{
			name:    "Get a managed worker",
			scopeId: managedPkiWorker.GetScopeId(),
			req:     &pbs.GetWorkerRequest{Id: managedPkiWorker.GetPublicId()},
			res:     &pbs.GetWorkerResponse{Item: wantManagedPkiWorker},
		},
		{
			name: "Get a non-existent Worker",
			req:  &pbs.GetWorkerRequest{Id: globals.WorkerPrefix + "_DoesntExis"},
			res:  nil,
			err:  handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name: "Wrong id prefix",
			req:  &pbs.GetWorkerRequest{Id: "j_1234567890"},
			res:  nil,
			err:  handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Space in id",
			req:  &pbs.GetWorkerRequest{Id: globals.WorkerPrefix + "_1 23456789"},
			res:  nil,
			err:  handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := NewService(context.Background(), repoFn, iamRepoFn, workerAuthRepoFn, nil)
			require.NoError(t, err, "Couldn't create new worker service.")

			got, err := s.GetWorker(auth.DisabledAuthTestContext(iamRepoFn, tc.scopeId), tc.req)
			if tc.err != nil {
				require.Error(t, err)
				assert.True(t, errors.Is(err, tc.err), "GetWorker(%+v) got error %v, wanted %v", tc.req, err, tc.err)
			} else {
				require.NoError(t, err)
			}
			assert.Empty(t, cmp.Diff(
				got,
				tc.res,
				protocmp.Transform(),
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
			), "GetWorker(%q) got response\n%q, wanted\n%q", tc.req, got, tc.res)
		})
	}
}

func TestList(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrap)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	rw := db.New(conn)
	kms := kms.TestKms(t, conn, wrap)
	repoFn := func() (*server.Repository, error) {
		return server.NewRepository(ctx, rw, rw, kms)
	}
	oldDownstramFn := downstreamWorkers
	t.Cleanup(func() {
		downstreamWorkers = oldDownstramFn
	})
	connectedDownstreams := []string{"first", "second", "third"}
	downstreamWorkers = func(_ context.Context, id string, _ downstream.Graph) []string {
		return connectedDownstreams
	}

	workerAuthRepo, err := server.NewRepositoryStorage(ctx, rw, rw, kms)
	require.NoError(t, err)
	workerAuthRepoFn := func() (*server.WorkerAuthRepositoryStorage, error) {
		return workerAuthRepo, nil
	}

	var wantKmsWorkers []*pb.Worker
	for i := 0; i < 10; i++ {
		w := server.TestKmsWorker(t, conn, wrap, server.WithName(fmt.Sprintf("kms-worker%d", i)))
		kmsAuthzActions := make([]string, len(testAuthorizedActions))
		copy(kmsAuthzActions, testAuthorizedActions)
		wantKmsWorkers = append(wantKmsWorkers, &pb.Worker{
			Id:                                 w.GetPublicId(),
			ScopeId:                            w.GetScopeId(),
			Scope:                              &scopes.ScopeInfo{Id: w.GetScopeId(), Type: scope.Global.String(), Name: scope.Global.String(), Description: "Global Scope"},
			CreatedTime:                        w.CreateTime.GetTimestamp(),
			UpdatedTime:                        w.UpdateTime.GetTimestamp(),
			Version:                            w.GetVersion(),
			Name:                               wrapperspb.String(w.GetName()),
			AuthorizedActions:                  strutil.StrListDelete(kmsAuthzActions, action.Update.String()),
			ActiveConnectionCount:              &wrapperspb.UInt32Value{Value: 0},
			Address:                            w.GetAddress(),
			Type:                               KmsWorkerType,
			LastStatusTime:                     w.GetLastStatusTime().GetTimestamp(),
			ReleaseVersion:                     w.ReleaseVersion,
			DirectlyConnectedDownstreamWorkers: connectedDownstreams,
			LocalStorageState:                  server.UnknownLocalStorageState.String(),
		})
	}

	var wantPkiWorkers []*pb.Worker
	for i := 0; i < 10; i++ {
		w := server.TestPkiWorker(t, conn, wrap, server.WithName(fmt.Sprintf("pki-worker%d", i)))
		wantPkiWorkers = append(wantPkiWorkers, &pb.Worker{
			Id:                                 w.GetPublicId(),
			ScopeId:                            w.GetScopeId(),
			Scope:                              &scopes.ScopeInfo{Id: w.GetScopeId(), Type: scope.Global.String(), Name: scope.Global.String(), Description: "Global Scope"},
			CreatedTime:                        w.CreateTime.GetTimestamp(),
			UpdatedTime:                        w.UpdateTime.GetTimestamp(),
			Version:                            w.GetVersion(),
			Name:                               wrapperspb.String(w.GetName()),
			ActiveConnectionCount:              &wrapperspb.UInt32Value{Value: 0},
			AuthorizedActions:                  testAuthorizedActions,
			Address:                            w.GetAddress(),
			Type:                               PkiWorkerType,
			LastStatusTime:                     w.GetLastStatusTime().GetTimestamp(),
			ReleaseVersion:                     w.ReleaseVersion,
			DirectlyConnectedDownstreamWorkers: connectedDownstreams,
			LocalStorageState:                  server.UnknownLocalStorageState.String(),
		})
	}

	cases := []struct {
		name string
		req  *pbs.ListWorkersRequest
		res  *pbs.ListWorkersResponse
		err  error
	}{
		{
			name: "List All Workers",
			req:  &pbs.ListWorkersRequest{ScopeId: scope.Global.String()},
			res:  &pbs.ListWorkersResponse{Items: append(wantKmsWorkers, wantPkiWorkers...)},
		},
		{
			name: "List global workers recursively",
			req:  &pbs.ListWorkersRequest{ScopeId: "global", Recursive: true},
			res: &pbs.ListWorkersResponse{
				Items: append(wantKmsWorkers, wantPkiWorkers...),
			},
		},
		{
			name: "Filter to a single worker of each type",
			req:  &pbs.ListWorkersRequest{ScopeId: "global", Recursive: true, Filter: `"/item/name"=="kms-worker2" or "/item/name"=="pki-worker2"`},
			res: &pbs.ListWorkersResponse{
				Items: []*pb.Worker{wantKmsWorkers[2], wantPkiWorkers[2]},
			},
		},
		{
			name: "Filter to 2 workers of each type",
			req:  &pbs.ListWorkersRequest{ScopeId: "global", Recursive: true, Filter: `"/item/name" matches "kms-worker[23]" or "/item/name" matches "pki-worker[23]"`},
			res: &pbs.ListWorkersResponse{
				Items: []*pb.Worker{wantKmsWorkers[2], wantKmsWorkers[3], wantPkiWorkers[2], wantPkiWorkers[3]},
			},
		},
		{
			name: "Filter to no workers",
			req:  &pbs.ListWorkersRequest{ScopeId: "global", Recursive: true, Filter: `"/item/id"=="doesntmatch"`},
			res:  &pbs.ListWorkersResponse{},
		},
		{
			name: "Filter Bad Format",
			req:  &pbs.ListWorkersRequest{ScopeId: "global", Filter: `"//id/"=="bad"`},
			err:  handlers.InvalidArgumentErrorf("bad format", nil),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			s, err := NewService(context.Background(), repoFn, iamRepoFn, workerAuthRepoFn, nil)
			require.NoError(err, "Couldn't create new worker service.")

			// Test with a non-anon user
			got, gErr := s.ListWorkers(auth.DisabledAuthTestContext(iamRepoFn, tc.req.GetScopeId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "ListWorkers(%q) got error %v, wanted %v", tc.req.GetScopeId(), gErr, tc.err)
				return
			}
			require.NoError(gErr)
			sort.Slice(got.Items, func(i, j int) bool {
				return got.Items[i].GetName().GetValue() < got.Items[j].GetName().GetValue()
			})
			require.NoError(gErr)
			sort.Slice(tc.res.Items, func(i, j int) bool {
				return tc.res.Items[i].GetName().GetValue() < tc.res.Items[j].GetName().GetValue()
			})
			assert.Empty(cmp.Diff(
				got,
				tc.res,
				protocmp.Transform(),
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
			), "ListWorkers(%q) got response %q, wanted %q", tc.req.GetScopeId(), got, tc.res)

			// Test the anon case
			got, gErr = s.ListWorkers(auth.DisabledAuthTestContext(iamRepoFn, tc.req.GetScopeId(), auth.WithUserId(globals.AnonymousUserId)), tc.req)
			require.NoError(gErr)
			assert.Len(got.Items, len(tc.res.Items))
			for _, item := range got.GetItems() {
				require.Nil(item.CreatedTime)
				require.Nil(item.UpdatedTime)
				require.Zero(item.Version)
			}
		})
	}
}

func TestDelete(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrap)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	rw := db.New(conn)
	kms := kms.TestKms(t, conn, wrap)
	repoFn := func() (*server.Repository, error) {
		return server.NewRepository(ctx, rw, rw, kms)
	}

	workerAuthRepo, err := server.NewRepositoryStorage(ctx, rw, rw, kms)
	require.NoError(t, err)
	workerAuthRepoFn := func() (*server.WorkerAuthRepositoryStorage, error) {
		return workerAuthRepo, nil
	}

	s, err := NewService(ctx, repoFn, iamRepoFn, workerAuthRepoFn, nil)
	require.NoError(t, err, "Error when getting new worker service.")

	wUnmanaged := server.TestKmsWorker(t, conn, wrap, server.WithWorkerTags(&server.Tag{
		Key:   "foo",
		Value: "bar",
	}))
	wManaged := server.TestKmsWorker(t, conn, wrap, server.WithWorkerTags(&server.Tag{
		Key:   server.ManagedWorkerTag,
		Value: "bar",
	}))

	cases := []struct {
		name        string
		scopeId     string
		req         *pbs.DeleteWorkerRequest
		res         *pbs.DeleteWorkerResponse
		err         error
		errContains string
	}{
		{
			name:    "Delete an Existing Worker",
			scopeId: wUnmanaged.GetScopeId(),
			req: &pbs.DeleteWorkerRequest{
				Id: wUnmanaged.GetPublicId(),
			},
		},
		{
			name:    "Delete bad worker id",
			scopeId: wUnmanaged.GetScopeId(),
			req: &pbs.DeleteWorkerRequest{
				Id: globals.WorkerPrefix + "_doesntexis",
			},
			err: handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name:    "Bad Worker Id formatting",
			scopeId: wUnmanaged.GetScopeId(),
			req: &pbs.DeleteWorkerRequest{
				Id: "bad_format",
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name:    "Cannot delete managed worker",
			scopeId: wManaged.GetScopeId(),
			req: &pbs.DeleteWorkerRequest{
				Id: wManaged.GetPublicId(),
			},
			err:         handlers.ApiErrorWithCode(codes.InvalidArgument),
			errContains: "Managed workers cannot be deleted",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, gErr := s.DeleteWorker(auth.DisabledAuthTestContext(iamRepoFn, tc.scopeId), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "DeleteWorker(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
			}
			if tc.errContains != "" {
				require.Error(gErr)
				assert.Contains(gErr.Error(), tc.errContains)
			}
			assert.EqualValuesf(tc.res, got, "DeleteWorker(%+v) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestUpdate(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	ctx := context.Background()
	rw := db.New(conn)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	repo, err := server.NewRepository(ctx, rw, rw, kms)
	require.NoError(t, err)
	repoFn := func() (*server.Repository, error) {
		return repo, nil
	}

	workerAuthRepo, err := server.NewRepositoryStorage(ctx, rw, rw, kms)
	require.NoError(t, err)
	workerAuthRepoFn := func() (*server.WorkerAuthRepositoryStorage, error) {
		return workerAuthRepo, nil
	}
	oldDownstramFn := downstreamWorkers
	t.Cleanup(func() {
		downstreamWorkers = oldDownstramFn
	})
	connectedDownstreams := []string{"first", "second", "third"}
	downstreamWorkers = func(_ context.Context, id string, _ downstream.Graph) []string {
		return connectedDownstreams
	}

	pkiWkr := server.TestPkiWorker(t, conn, wrapper,
		server.WithName("default"),
		server.WithDescription("default"))

	pkiKmsWkr := server.TestPkiWorker(t, conn, wrapper,
		server.WithName("default-kms"),
		server.WithDescription("default-kms"),
		server.WithNewIdFunc(func(ctx context.Context) (string, error) {
			return server.NewWorkerIdFromScopeAndName(ctx, scope.Global.String(), "default-kms")
		}),
	)

	pkiVersion := pkiWkr.GetVersion()
	pkiKmsVersion := pkiKmsWkr.GetVersion()

	resetWorker := func() {
		pkiVersion = pkiWkr.Version + 1
		pkiKmsVersion = pkiKmsWkr.Version + 1
		wkr, _, err := repo.UpdateWorker(context.Background(), pkiWkr, pkiVersion, []string{"Name", "Description"})
		require.NoError(t, err, "Failed to reset pki worker.")
		pkiVersion = wkr.Version
	}

	wCreated := pkiWkr.GetCreateTime().GetTimestamp().AsTime()
	toMerge := func(wkr *server.Worker) *pbs.UpdateWorkerRequest {
		return &pbs.UpdateWorkerRequest{
			Id: wkr.GetPublicId(),
		}
	}
	workerService, err := NewService(ctx, repoFn, iamRepoFn, workerAuthRepoFn, nil)
	require.NoError(t, err)
	expectedScope := &scopes.ScopeInfo{Id: scope.Global.String(), Type: scope.Global.String(), Name: scope.Global.String(), Description: "Global Scope"}

	cases := []struct {
		name      string
		reqIdFunc func(*server.Worker) string
		req       *pbs.UpdateWorkerRequest
		res       func(*server.Worker) *pbs.UpdateWorkerResponse
		err       error
	}{
		{
			name: "Update an Existing Worker",
			req: &pbs.UpdateWorkerRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name", "description"},
				},
				Item: &pb.Worker{
					Name:        wrapperspb.String("name"),
					Description: wrapperspb.String("desc"),
				},
			},
			res: func(wkr *server.Worker) *pbs.UpdateWorkerResponse {
				return &pbs.UpdateWorkerResponse{
					Item: &pb.Worker{
						Id:                                 wkr.GetPublicId(),
						ScopeId:                            wkr.GetScopeId(),
						Scope:                              expectedScope,
						Name:                               wrapperspb.String("name"),
						Description:                        wrapperspb.String("desc"),
						CreatedTime:                        wkr.GetCreateTime().GetTimestamp(),
						ActiveConnectionCount:              &wrapperspb.UInt32Value{Value: 0},
						LastStatusTime:                     wkr.GetLastStatusTime().GetTimestamp(),
						AuthorizedActions:                  testAuthorizedActions,
						Type:                               PkiWorkerType,
						DirectlyConnectedDownstreamWorkers: connectedDownstreams,
						LocalStorageState:                  server.UnknownLocalStorageState.String(),
					},
				}
			},
		},
		{
			name: "Multiple Paths in single string",
			req: &pbs.UpdateWorkerRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name,description,type"},
				},
				Item: &pb.Worker{
					Name:        wrapperspb.String("name"),
					Description: wrapperspb.String("default"),
				},
			},
			res: func(wkr *server.Worker) *pbs.UpdateWorkerResponse {
				return &pbs.UpdateWorkerResponse{
					Item: &pb.Worker{
						Id:                                 wkr.GetPublicId(),
						ScopeId:                            wkr.GetScopeId(),
						Scope:                              expectedScope,
						Name:                               wrapperspb.String("name"),
						Description:                        wrapperspb.String("default"),
						ActiveConnectionCount:              &wrapperspb.UInt32Value{Value: 0},
						CreatedTime:                        wkr.GetCreateTime().GetTimestamp(),
						LastStatusTime:                     wkr.GetLastStatusTime().GetTimestamp(),
						AuthorizedActions:                  testAuthorizedActions,
						Type:                               PkiWorkerType,
						DirectlyConnectedDownstreamWorkers: connectedDownstreams,
						LocalStorageState:                  server.UnknownLocalStorageState.String(),
					},
				}
			},
		},
		{
			name: "cant update address",
			req: &pbs.UpdateWorkerRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"address"},
				},
				Item: &pb.Worker{
					Address: "updated",
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "No Update Mask",
			req: &pbs.UpdateWorkerRequest{
				Item: &pb.Worker{
					Name:        wrapperspb.String("updated name"),
					Description: wrapperspb.String("updated desc"),
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Empty Path",
			req: &pbs.UpdateWorkerRequest{
				UpdateMask: &field_mask.FieldMask{Paths: []string{}},
				Item: &pb.Worker{
					Name:        wrapperspb.String("updated name"),
					Description: wrapperspb.String("updated desc"),
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Only non-existent paths in Mask",
			req: &pbs.UpdateWorkerRequest{
				UpdateMask: &field_mask.FieldMask{Paths: []string{"nonexistent_field"}},
				Item: &pb.Worker{
					Name:        wrapperspb.String("updated name"),
					Description: wrapperspb.String("updated desc"),
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Unset Name",
			req: &pbs.UpdateWorkerRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name"},
				},
				Item: &pb.Worker{
					Description: wrapperspb.String("ignored"),
				},
			},
			res: func(wkr *server.Worker) *pbs.UpdateWorkerResponse {
				return &pbs.UpdateWorkerResponse{
					Item: &pb.Worker{
						Id:                                 wkr.GetPublicId(),
						ScopeId:                            wkr.GetScopeId(),
						Scope:                              expectedScope,
						Description:                        wrapperspb.String(wkr.Description),
						ActiveConnectionCount:              &wrapperspb.UInt32Value{Value: 0},
						CreatedTime:                        wkr.GetCreateTime().GetTimestamp(),
						LastStatusTime:                     wkr.GetLastStatusTime().GetTimestamp(),
						AuthorizedActions:                  testAuthorizedActions,
						Type:                               PkiWorkerType,
						DirectlyConnectedDownstreamWorkers: connectedDownstreams,
						LocalStorageState:                  server.UnknownLocalStorageState.String(),
					},
				}
			},
		},
		{
			name: "Unset Description",
			req: &pbs.UpdateWorkerRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"description"},
				},
				Item: &pb.Worker{
					Name: wrapperspb.String("ignored"),
				},
			},
			res: func(wkr *server.Worker) *pbs.UpdateWorkerResponse {
				ret := &pbs.UpdateWorkerResponse{
					Item: &pb.Worker{
						Id:                                 wkr.GetPublicId(),
						ScopeId:                            wkr.GetScopeId(),
						Scope:                              expectedScope,
						CreatedTime:                        wkr.GetCreateTime().GetTimestamp(),
						ActiveConnectionCount:              &wrapperspb.UInt32Value{Value: 0},
						LastStatusTime:                     wkr.GetLastStatusTime().GetTimestamp(),
						AuthorizedActions:                  testAuthorizedActions,
						Type:                               PkiWorkerType,
						DirectlyConnectedDownstreamWorkers: connectedDownstreams,
						LocalStorageState:                  server.UnknownLocalStorageState.String(),
					},
				}
				// In the previous test, the name will now be blank if it's the
				// non-kms worker so must add it in to expected
				if wkr.PublicId == pkiKmsWkr.PublicId {
					ret.Item.Name = wrapperspb.String(wkr.Name)
				}
				return ret
			},
		},
		{
			name: "Update Only Name",
			req: &pbs.UpdateWorkerRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name"},
				},
				Item: &pb.Worker{
					Name:        wrapperspb.String("updated"),
					Description: wrapperspb.String("ignored"),
				},
			},
			res: func(wkr *server.Worker) *pbs.UpdateWorkerResponse {
				ret := &pbs.UpdateWorkerResponse{
					Item: &pb.Worker{
						Id:                                 wkr.GetPublicId(),
						ScopeId:                            wkr.GetScopeId(),
						Scope:                              expectedScope,
						Name:                               wrapperspb.String("updated"),
						CreatedTime:                        wkr.GetCreateTime().GetTimestamp(),
						ActiveConnectionCount:              &wrapperspb.UInt32Value{Value: 0},
						LastStatusTime:                     wkr.GetLastStatusTime().GetTimestamp(),
						AuthorizedActions:                  testAuthorizedActions,
						Type:                               PkiWorkerType,
						DirectlyConnectedDownstreamWorkers: connectedDownstreams,
						LocalStorageState:                  server.UnknownLocalStorageState.String(),
					},
				}
				// The name will not be updated if it's the pki-kms worker
				if wkr.PublicId == pkiKmsWkr.PublicId {
					ret.Item.Name = wrapperspb.String(wkr.Name)
				}
				return ret
			},
		},
		{
			name: "Update Only Description",
			req: &pbs.UpdateWorkerRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"description"},
				},
				Item: &pb.Worker{
					Name:        wrapperspb.String("ignored"),
					Description: wrapperspb.String("notignored"),
				},
			},
			res: func(wkr *server.Worker) *pbs.UpdateWorkerResponse {
				ret := &pbs.UpdateWorkerResponse{
					Item: &pb.Worker{
						Id:                                 wkr.GetPublicId(),
						ScopeId:                            wkr.GetScopeId(),
						Scope:                              expectedScope,
						Name:                               wrapperspb.String("updated"),
						ActiveConnectionCount:              &wrapperspb.UInt32Value{Value: 0},
						Description:                        wrapperspb.String("notignored"),
						CreatedTime:                        wkr.GetCreateTime().GetTimestamp(),
						LastStatusTime:                     wkr.GetLastStatusTime().GetTimestamp(),
						AuthorizedActions:                  testAuthorizedActions,
						Type:                               PkiWorkerType,
						DirectlyConnectedDownstreamWorkers: connectedDownstreams,
						LocalStorageState:                  server.UnknownLocalStorageState.String(),
					},
				}
				// The name will not have been updated previously if it's the pki-kms worker
				if wkr.PublicId == pkiKmsWkr.PublicId {
					ret.Item.Name = wrapperspb.String(wkr.Name)
				}
				return ret
			},
		},
		{
			name: "Update a Non Existing Worker",
			req: &pbs.UpdateWorkerRequest{
				Id: globals.WorkerPrefix + "_DoesntExis",
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"description"},
				},
				Item: &pb.Worker{
					Description: wrapperspb.String("desc"),
				},
			},
			err: handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name: "Cant change Id pki worker",
			reqIdFunc: func(worker *server.Worker) string {
				return worker.GetPublicId()
			},
			req: &pbs.UpdateWorkerRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"id"},
				},
				Item: &pb.Worker{
					Id: "w_somethinge",
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Cant specify Created Time",
			req: &pbs.UpdateWorkerRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"created_time"},
				},
				Item: &pb.Worker{
					CreatedTime: timestamppb.Now(),
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Cant specify Updated Time",
			req: &pbs.UpdateWorkerRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"updated_time"},
				},
				Item: &pb.Worker{
					UpdatedTime: timestamppb.Now(),
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Cant specify tags",
			req: &pbs.UpdateWorkerRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"tags"},
				},
				Item: &pb.Worker{
					ConfigTags: map[string]*structpb.ListValue{
						"foo": structListValue(t, "bar"),
					},
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Cant specify canonical tags",
			req: &pbs.UpdateWorkerRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"canonical_tags"},
				},
				Item: &pb.Worker{
					CanonicalTags: map[string]*structpb.ListValue{
						"foo": structListValue(t, "bar"),
					},
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Cant specify address",
			req: &pbs.UpdateWorkerRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{globals.AddressField},
				},
				Item: &pb.Worker{
					Address: "should_fail",
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Invalid name- uppercase",
			req: &pbs.UpdateWorkerRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name", "description", "address"},
				},
				Item: &pb.Worker{
					Name: wrapperspb.String("BADNAME"),
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Invalid name- non-printable",
			req: &pbs.UpdateWorkerRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name", "description", "address"},
				},
				Item: &pb.Worker{
					Name: wrapperspb.String("\x00"),
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Invalid description- nonprintable",
			req: &pbs.UpdateWorkerRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name", "description", "address"},
				},
				Item: &pb.Worker{
					Description: wrapperspb.String("\x00"),
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		for _, wkr := range []*server.Worker{pkiWkr, pkiKmsWkr} {
			t.Run(fmt.Sprintf("%s-%s", tc.name, wkr.Name), func(t *testing.T) {
				if wkr.PublicId == pkiWkr.PublicId {
					tc.req.Item.Version = pkiVersion
				} else {
					tc.req.Item.Version = pkiKmsVersion
				}

				req := proto.Clone(toMerge(wkr)).(*pbs.UpdateWorkerRequest)
				proto.Merge(req, tc.req)
				if tc.reqIdFunc != nil {
					req.Id = tc.reqIdFunc(wkr)
				}

				// Search through update masks to see if we're updating name
				var basicInfoChange bool
				if tc.req != nil && tc.req.UpdateMask != nil {
					for _, field := range tc.req.UpdateMask.Paths {
						if strings.ToLower(field) == "name" || strings.ToLower(field) == "description" {
							basicInfoChange = true
						}
						if strings.Contains(field, ",") {
							splitStr := strings.Split(field, ",")
							for _, field := range splitStr {
								if strings.ToLower(field) == "name" || strings.ToLower(field) == "description" {
									basicInfoChange = true
								}
							}
						}
					}
				}

				got, gErr := workerService.UpdateWorker(auth.DisabledAuthTestContext(iamRepoFn, scope.Global.String()), req)
				// If it's a PKI-KMS worker and we wouldn't otherwise expect an
				// error but we tried a name change, ensure we see the expected
				// error here.
				if wkr.PublicId == pkiKmsWkr.PublicId && basicInfoChange && tc.err == nil {
					require.Error(t, gErr)
					assert.Contains(t, gErr.Error(), "KMS workers cannot be updated through the API")
					assert.True(t, errors.Is(gErr, handlers.ApiErrorWithCode(codes.InvalidArgument)))
					return
				}
				if tc.err != nil {
					require.Error(t, gErr)
					assert.True(t, errors.Is(gErr, tc.err), "UpdateWorker(%+v) got error %v, wanted %v", req, gErr, tc.err)
					assert.Nil(t, got)
					return
				}

				// Should not have nil got at this point
				require.NotNil(t, got)

				if tc.err == nil {
					defer resetWorker()
				}

				expRes := tc.res(wkr)

				assert.NotNilf(t, tc.res, "Expected UpdateWorker response to be nil, but was %v", got)
				gotUpdateTime := got.GetItem().GetUpdatedTime().AsTime()
				// Verify updated set after it was created
				assert.True(t, gotUpdateTime.After(wCreated), "Updated resource should have been updated after its creation. Was updated %v, which is after %v", gotUpdateTime, wCreated)

				// Clear all values which are hard to compare against.
				got.Item.UpdatedTime, expRes.Item.UpdatedTime = nil, nil

				expRes.Item.Version = tc.req.Item.Version + 1

				assert.Empty(t, cmp.Diff(
					got,
					expRes,
					protocmp.Transform(),
					cmpopts.SortSlices(func(a, b string) bool {
						return a < b
					}),
				), "UpdateWorker(%q) got response %q, wanted %q", req, got, expRes)
			})
		}
	}
}

func TestUpdate_DeprecatedKMS(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	ctx := context.Background()
	rw := db.New(conn)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	repo, err := server.NewRepository(ctx, rw, rw, kms)
	require.NoError(t, err)
	repoFn := func() (*server.Repository, error) {
		return repo, nil
	}

	workerAuthRepo, err := server.NewRepositoryStorage(ctx, rw, rw, kms)
	require.NoError(t, err)
	workerAuthRepoFn := func() (*server.WorkerAuthRepositoryStorage, error) {
		return workerAuthRepo, nil
	}

	wkr := server.TestKmsWorker(t, conn, wrapper,
		server.WithName("default"),
		server.WithDescription("default"))

	toMerge := &pbs.UpdateWorkerRequest{
		Id: wkr.GetPublicId(),
	}
	workerService, err := NewService(ctx, repoFn, iamRepoFn, workerAuthRepoFn, nil)
	require.NoError(t, err)

	cases := []struct {
		name        string
		req         *pbs.UpdateWorkerRequest
		res         *pbs.UpdateWorkerResponse
		errContains string
	}{
		{
			name: "Cant set name",
			req: &pbs.UpdateWorkerRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name"},
				},
				Item: &pb.Worker{
					Name: wrapperspb.String("name"),
				},
			},
			errContains: "KMS workers cannot be updated through the API",
		},
		{
			name: "Cant set description",
			req: &pbs.UpdateWorkerRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"description"},
				},
				Item: &pb.Worker{
					Description: wrapperspb.String("description"),
				},
			},
			errContains: "KMS workers cannot be updated through the API",
		},
		{
			name: "Cant set address",
			req: &pbs.UpdateWorkerRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"address"},
				},
				Item: &pb.Worker{
					Address: "address",
				},
			},
			errContains: "This is a read only field.",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := proto.Clone(toMerge).(*pbs.UpdateWorkerRequest)
			proto.Merge(req, tc.req)
			req.Item.Version = wkr.GetVersion()
			got, gErr := workerService.UpdateWorker(auth.DisabledAuthTestContext(iamRepoFn, scope.Global.String()), req)
			assert.Error(t, gErr)
			assert.Nil(t, got)
			assert.Contains(t, gErr.Error(), tc.errContains)
			assert.True(t, errors.Is(gErr, handlers.ApiErrorWithCode(codes.InvalidArgument)))
		})
	}
}

func TestUpdate_BadVersion(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	workerAuthRepo, err := server.NewRepositoryStorage(ctx, rw, rw, kms)
	require.NoError(t, err)
	workerAuthRepoFn := func() (*server.WorkerAuthRepositoryStorage, error) {
		return workerAuthRepo, nil
	}

	_, proj := iam.TestScopes(t, iamRepo)

	repo, err := server.NewRepository(ctx, rw, rw, kms)
	require.NoError(t, err, "Couldn't create new worker repo.")
	repoFn := func() (*server.Repository, error) {
		return repo, nil
	}

	workerService, err := NewService(ctx, repoFn, iamRepoFn, workerAuthRepoFn, nil)
	require.NoError(t, err, "Failed to create a new host set service.")

	wkr := server.TestPkiWorker(t, conn, wrapper)

	upTar, err := workerService.UpdateWorker(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId()), &pbs.UpdateWorkerRequest{
		Id: wkr.GetPublicId(),
		Item: &pb.Worker{
			Description: wrapperspb.String("updated"),
			Version:     72,
		},
		UpdateMask: &field_mask.FieldMask{Paths: []string{"description"}},
	})
	assert.Nil(t, upTar)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, handlers.NotFoundError()), "Got %v, wanted not found error.", err)
}

func TestCreateWorkerLed(t *testing.T) {
	testCtx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	testRootWrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, testRootWrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	rw := db.New(conn)
	testKms := kms.TestKms(t, conn, testRootWrapper)
	repoFn := func() (*server.Repository, error) {
		return server.NewRepository(testCtx, rw, rw, testKms)
	}

	workerAuthRepo, err := server.NewRepositoryStorage(testCtx, rw, rw, testKms)
	require.NoError(t, err)
	workerAuthRepoFn := func() (*server.WorkerAuthRepositoryStorage, error) {
		return workerAuthRepo, nil
	}

	testSrv, err := NewService(testCtx, repoFn, iamRepoFn, workerAuthRepoFn, nil)
	require.NoError(t, err, "Error when getting new worker service.")

	// Get an initial set of authorized node credentials
	rootStorage, err := server.NewRepositoryStorage(testCtx, rw, rw, testKms)
	require.NoError(t, err)
	_, err = rotation.RotateRootCertificates(testCtx, rootStorage)
	require.NoError(t, err)

	fetchReqFn := func() string {
		// This happens on the worker
		fileStorage, err := file.New(testCtx)
		require.NoError(t, err)
		defer func() { fileStorage.Cleanup(testCtx) }()

		nodeCreds, err := types.NewNodeCredentials(testCtx, fileStorage)
		require.NoError(t, err)
		// Create request using worker id
		fetchReq, err := nodeCreds.CreateFetchNodeCredentialsRequest(testCtx)
		require.NoError(t, err)

		fetchEncoded, err := proto.Marshal(fetchReq)
		require.NoError(t, err)

		return base58.Encode(fetchEncoded)
	}

	tests := []struct {
		name            string
		scopeId         string
		service         Service
		req             *pbs.CreateWorkerLedRequest
		res             *pbs.CreateWorkerLedResponse
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name:    "invalid-scope",
			service: testSrv,
			scopeId: scope.Global.String(),
			req: &pbs.CreateWorkerLedRequest{
				Item: &pb.Worker{
					ScopeId:                  "invalid-scope",
					WorkerGeneratedAuthToken: &wrapperspb.StringValue{Value: fetchReqFn()},
				},
			},
			wantErr:         true,
			wantErrIs:       handlers.ApiErrorWithCode(codes.InvalidArgument),
			wantErrContains: "Must be 'global'",
		},
		{
			name:    "missing-node-credentials-token",
			service: testSrv,
			scopeId: scope.Global.String(),
			req: &pbs.CreateWorkerLedRequest{
				Item: &pb.Worker{
					ScopeId: scope.Global.String(),
				},
			},
			wantErr:         true,
			wantErrIs:       handlers.ApiErrorWithCode(codes.InvalidArgument),
			wantErrContains: globals.WorkerGeneratedAuthTokenField,
		},
		{
			name:    "invalid-id",
			service: testSrv,
			scopeId: scope.Global.String(),
			req: &pbs.CreateWorkerLedRequest{
				Item: &pb.Worker{
					ScopeId:                  scope.Global.String(),
					WorkerGeneratedAuthToken: &wrapperspb.StringValue{Value: fetchReqFn()},
					Id:                       "invalid-id",
				},
			},
			wantErr:         true,
			wantErrIs:       handlers.ApiErrorWithCode(codes.InvalidArgument),
			wantErrContains: globals.IdField,
		},
		{
			name:    "invalid-address",
			service: testSrv,
			scopeId: scope.Global.String(),
			req: &pbs.CreateWorkerLedRequest{
				Item: &pb.Worker{
					ScopeId:                  scope.Global.String(),
					WorkerGeneratedAuthToken: &wrapperspb.StringValue{Value: fetchReqFn()},
					Address:                  "invalid-address",
				},
			},
			wantErr:         true,
			wantErrIs:       handlers.ApiErrorWithCode(codes.InvalidArgument),
			wantErrContains: globals.AddressField,
		},
		{
			name:    "invalid-config-tags",
			service: testSrv,
			scopeId: scope.Global.String(),
			req: &pbs.CreateWorkerLedRequest{
				Item: &pb.Worker{
					ScopeId:                  scope.Global.String(),
					WorkerGeneratedAuthToken: &wrapperspb.StringValue{Value: fetchReqFn()},
					ConfigTags: map[string]*structpb.ListValue{
						"invalid": {Values: []*structpb.Value{
							structpb.NewStringValue("invalid-tags"),
						}},
					},
				},
			},
			wantErr:         true,
			wantErrIs:       handlers.ApiErrorWithCode(codes.InvalidArgument),
			wantErrContains: globals.ConfigTagsField,
		},
		{
			name:    "invalid-canonical-tags",
			service: testSrv,
			scopeId: scope.Global.String(),
			req: &pbs.CreateWorkerLedRequest{
				Item: &pb.Worker{
					ScopeId:                  scope.Global.String(),
					WorkerGeneratedAuthToken: &wrapperspb.StringValue{Value: fetchReqFn()},
					CanonicalTags: map[string]*structpb.ListValue{
						"invalid": {Values: []*structpb.Value{
							structpb.NewStringValue("invalid-canonical-tags"),
						}},
					},
				},
			},
			wantErr:         true,
			wantErrIs:       handlers.ApiErrorWithCode(codes.InvalidArgument),
			wantErrContains: globals.CanonicalTagsField,
		},
		{
			name:    "invalid-last-status-time",
			service: testSrv,
			scopeId: scope.Global.String(),
			req: &pbs.CreateWorkerLedRequest{
				Item: &pb.Worker{
					ScopeId:                  scope.Global.String(),
					WorkerGeneratedAuthToken: &wrapperspb.StringValue{Value: fetchReqFn()},
					LastStatusTime:           timestamppb.Now(),
				},
			},
			wantErr:         true,
			wantErrIs:       handlers.ApiErrorWithCode(codes.InvalidArgument),
			wantErrContains: globals.LastStatusTimeField,
		},
		{
			name:    "invalid-authorized-actions",
			service: testSrv,
			scopeId: scope.Global.String(),
			req: &pbs.CreateWorkerLedRequest{
				Item: &pb.Worker{
					ScopeId:                  scope.Global.String(),
					WorkerGeneratedAuthToken: &wrapperspb.StringValue{Value: fetchReqFn()},
					AuthorizedActions:        []string{"invalid-authorized-actions"},
				},
			},
			wantErr:         true,
			wantErrIs:       handlers.ApiErrorWithCode(codes.InvalidArgument),
			wantErrContains: globals.AuthorizedActionsField,
		},
		{
			name:    "invalid-create-time",
			service: testSrv,
			scopeId: scope.Global.String(),
			req: &pbs.CreateWorkerLedRequest{
				Item: &pb.Worker{
					ScopeId:                  scope.Global.String(),
					WorkerGeneratedAuthToken: &wrapperspb.StringValue{Value: fetchReqFn()},
					CreatedTime:              timestamppb.Now(),
				},
			},
			wantErr:         true,
			wantErrIs:       handlers.ApiErrorWithCode(codes.InvalidArgument),
			wantErrContains: globals.CreatedTimeField,
		},
		{
			name:    "invalid-update-time",
			service: testSrv,
			scopeId: scope.Global.String(),
			req: &pbs.CreateWorkerLedRequest{
				Item: &pb.Worker{
					ScopeId:                  scope.Global.String(),
					WorkerGeneratedAuthToken: &wrapperspb.StringValue{Value: fetchReqFn()},
					UpdatedTime:              timestamppb.Now(),
				},
			},
			wantErr:         true,
			wantErrIs:       handlers.ApiErrorWithCode(codes.InvalidArgument),
			wantErrContains: globals.UpdatedTimeField,
		},
		{
			name:    "invalid-version",
			service: testSrv,
			scopeId: scope.Global.String(),
			req: &pbs.CreateWorkerLedRequest{
				Item: &pb.Worker{
					ScopeId:                  scope.Global.String(),
					WorkerGeneratedAuthToken: &wrapperspb.StringValue{Value: fetchReqFn()},
					Version:                  1,
				},
			},
			wantErr:         true,
			wantErrIs:       handlers.ApiErrorWithCode(codes.InvalidArgument),
			wantErrContains: globals.VersionField,
		},
		{
			name:    "invalid-auth",
			service: testSrv,
			scopeId: "splat-auth-scope",
			req: &pbs.CreateWorkerLedRequest{
				Item: &pb.Worker{
					ScopeId:                  scope.Global.String(),
					WorkerGeneratedAuthToken: &wrapperspb.StringValue{Value: fetchReqFn()},
				},
			},
			wantErr:         true,
			wantErrContains: "non-existent scope \"splat-auth-scope\"",
		},
		{
			name:    "invalid-base58-encoding",
			service: testSrv,
			scopeId: scope.Global.String(),
			req: &pbs.CreateWorkerLedRequest{
				Item: &pb.Worker{
					ScopeId:                  scope.Global.String(),
					WorkerGeneratedAuthToken: &wrapperspb.StringValue{Value: "invalid;semicolon"},
				},
			},
			wantErr:         true,
			wantErrContains: "error decoding node_credentials_token",
		},
		{
			name:    "invalid-marshal",
			service: testSrv,
			scopeId: scope.Global.String(),
			req: &pbs.CreateWorkerLedRequest{
				Item: &pb.Worker{
					ScopeId:                  scope.Global.String(),
					WorkerGeneratedAuthToken: &wrapperspb.StringValue{Value: "notNodeCreds"},
				},
			},
			wantErr:         true,
			wantErrContains: "error unmarshaling node_credentials_token",
		},
		{
			name: "create-error",
			service: func() Service {
				repoFn := func() (*server.Repository, error) {
					return server.NewRepository(testCtx, rw, &db.Db{}, testKms)
				}
				testSrv, err := NewService(testCtx, repoFn, iamRepoFn, workerAuthRepoFn, nil)
				require.NoError(t, err, "Error when getting new worker service.")
				return testSrv
			}(),
			scopeId: scope.Global.String(),
			req: &pbs.CreateWorkerLedRequest{
				Item: &pb.Worker{
					ScopeId:                  scope.Global.String(),
					Name:                     &wrapperspb.StringValue{Value: "success"},
					Description:              &wrapperspb.StringValue{Value: "success-description"},
					WorkerGeneratedAuthToken: &wrapperspb.StringValue{Value: fetchReqFn()},
				},
			},
			wantErr:         true,
			wantErrContains: "error creating worker",
		},
		{
			name: "bad-repo-function-in-create",
			service: func() Service {
				// var cnt gives us a way for the repoFn to fail the 2nd time
				// it's called so we can get past the AuthRequest check in
				// CreateWorker(...) and test the createInRepo(...) failure
				// path if the repoFn returns and err.
				cnt := 0
				repoFn := func() (*server.Repository, error) {
					cnt = cnt + 1
					switch {
					case cnt > 1:
						return nil, errors.New(testCtx, errors.Internal, "bad-repo-function", "error creating repo")
					default:
						return server.NewRepository(testCtx, rw, rw, testKms)
					}
				}
				testSrv, err := NewService(testCtx, repoFn, iamRepoFn, workerAuthRepoFn, nil)
				require.NoError(t, err, "Error when getting new worker service.")
				return testSrv
			}(),
			scopeId: scope.Global.String(),
			req: &pbs.CreateWorkerLedRequest{
				Item: &pb.Worker{
					ScopeId:                  scope.Global.String(),
					Name:                     &wrapperspb.StringValue{Value: "success"},
					Description:              &wrapperspb.StringValue{Value: "success-description"},
					WorkerGeneratedAuthToken: &wrapperspb.StringValue{Value: fetchReqFn()},
				},
			},
			wantErr:         true,
			wantErrContains: "error creating worker: bad-repo-function: error creating repo",
		},
		{
			name:    "success",
			service: testSrv,
			scopeId: scope.Global.String(),
			req: &pbs.CreateWorkerLedRequest{
				Item: &pb.Worker{
					ScopeId:                  scope.Global.String(),
					Name:                     &wrapperspb.StringValue{Value: "success"},
					Description:              &wrapperspb.StringValue{Value: "success-description"},
					WorkerGeneratedAuthToken: &wrapperspb.StringValue{Value: fetchReqFn()},
				},
			},
			res: &pbs.CreateWorkerLedResponse{
				Item: &pb.Worker{
					ScopeId:               scope.Global.String(),
					Name:                  &wrapperspb.StringValue{Value: "success"},
					Description:           &wrapperspb.StringValue{Value: "success-description"},
					ActiveConnectionCount: &wrapperspb.UInt32Value{Value: 0},
					Version:               1,
					Type:                  PkiWorkerType,
				},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := tc.service.CreateWorkerLed(auth.DisabledAuthTestContext(iamRepoFn, tc.scopeId), tc.req)
			if tc.wantErr {
				require.Error(err)
				assert.Nil(got)
				if tc.wantErrIs != nil {
					assert.ErrorIs(err, tc.wantErrIs)
				}
				if tc.wantErrContains != "" {
					assert.Contains(err.Error(), tc.wantErrContains)
				}
				return
			}
			require.NoError(err)
			require.NotNil(got)
			{
				// we only need to check that these "read-only" fields were set
				// outbound. Other portions of the domain is responsible for
				// testing that these values are correct and there's no reason
				// to repeat those tests here.
				assert.NotEmpty(got.GetItem().GetId())
				assert.NotEmpty(got.GetItem().CreatedTime)
				assert.NotEmpty(got.GetItem().UpdatedTime)
				assert.NotEmpty(got.GetItem().Scope)
				assert.NotEmpty(got.GetItem().AuthorizedActions)
				{
					tc.res.Item.Id = got.GetItem().GetId()
					tc.res.Item.CreatedTime = got.GetItem().GetCreatedTime()
					tc.res.Item.UpdatedTime = got.GetItem().GetUpdatedTime()
					tc.res.Item.Scope = got.GetItem().Scope
					tc.res.Item.AuthorizedActions = got.GetItem().GetAuthorizedActions()
					tc.res.Item.LocalStorageState = got.GetItem().GetLocalStorageState()
					tc.res.Item.DirectlyConnectedDownstreamWorkers = got.GetItem().GetDirectlyConnectedDownstreamWorkers()
				}
			}
			assert.Equal(tc.res, got)
		})
	}
}

func TestCreateControllerLed(t *testing.T) {
	testCtx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	testRootWrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, testRootWrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	rw := db.New(conn)
	testKms := kms.TestKms(t, conn, testRootWrapper)
	repoFn := func() (*server.Repository, error) {
		return server.NewRepository(testCtx, rw, rw, testKms)
	}

	rootStorage, err := server.NewRepositoryStorage(testCtx, rw, rw, testKms)
	require.NoError(t, err)
	authRepoFn := func() (*server.WorkerAuthRepositoryStorage, error) {
		return rootStorage, nil
	}

	testSrv, err := NewService(testCtx, repoFn, iamRepoFn, authRepoFn, nil)
	require.NoError(t, err, "Error when getting new worker service.")

	// Get an initial set of authorized node credentials
	_, err = rotation.RotateRootCertificates(testCtx, rootStorage)
	require.NoError(t, err)

	fetchReqFn := func() string {
		// This happens on the worker
		fileStorage, err := file.New(testCtx)
		require.NoError(t, err)
		defer func() { fileStorage.Cleanup(testCtx) }()

		nodeCreds, err := types.NewNodeCredentials(testCtx, fileStorage)
		require.NoError(t, err)
		// Create request using worker id
		fetchReq, err := nodeCreds.CreateFetchNodeCredentialsRequest(testCtx)
		require.NoError(t, err)

		fetchEncoded, err := proto.Marshal(fetchReq)
		require.NoError(t, err)

		return base58.Encode(fetchEncoded)
	}

	tests := []struct {
		name            string
		scopeId         string
		service         Service
		req             *pbs.CreateControllerLedRequest
		res             *pbs.CreateControllerLedResponse
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name:    "invalid-scope",
			service: testSrv,
			scopeId: scope.Global.String(),
			req: &pbs.CreateControllerLedRequest{
				Item: &pb.Worker{
					ScopeId: "invalid-scope",
				},
			},
			wantErr:         true,
			wantErrIs:       handlers.ApiErrorWithCode(codes.InvalidArgument),
			wantErrContains: "Must be 'global'",
		},
		{
			name:    "supplied-node-auth-request",
			service: testSrv,
			scopeId: scope.Global.String(),
			req: &pbs.CreateControllerLedRequest{
				Item: &pb.Worker{
					ScopeId:                  scope.Global.String(),
					WorkerGeneratedAuthToken: &wrapperspb.StringValue{Value: fetchReqFn()},
				},
			},
			wantErr:         true,
			wantErrIs:       handlers.ApiErrorWithCode(codes.InvalidArgument),
			wantErrContains: globals.WorkerGeneratedAuthTokenField,
		},
		{
			name:    "invalid-id",
			service: testSrv,
			scopeId: scope.Global.String(),
			req: &pbs.CreateControllerLedRequest{
				Item: &pb.Worker{
					ScopeId: scope.Global.String(),
					Id:      "invalid-id",
				},
			},
			wantErr:         true,
			wantErrIs:       handlers.ApiErrorWithCode(codes.InvalidArgument),
			wantErrContains: globals.IdField,
		},
		{
			name:    "invalid-address",
			service: testSrv,
			scopeId: scope.Global.String(),
			req: &pbs.CreateControllerLedRequest{
				Item: &pb.Worker{
					ScopeId: scope.Global.String(),
					Address: "invalid-address",
				},
			},
			wantErr:         true,
			wantErrIs:       handlers.ApiErrorWithCode(codes.InvalidArgument),
			wantErrContains: globals.AddressField,
		},
		{
			name:    "invalid-config-tags",
			service: testSrv,
			scopeId: scope.Global.String(),
			req: &pbs.CreateControllerLedRequest{
				Item: &pb.Worker{
					ScopeId: scope.Global.String(),
					ConfigTags: map[string]*structpb.ListValue{
						"invalid": {Values: []*structpb.Value{
							structpb.NewStringValue("invalid-tags"),
						}},
					},
				},
			},
			wantErr:         true,
			wantErrIs:       handlers.ApiErrorWithCode(codes.InvalidArgument),
			wantErrContains: globals.ConfigTagsField,
		},
		{
			name:    "invalid-canonical-tags",
			service: testSrv,
			scopeId: scope.Global.String(),
			req: &pbs.CreateControllerLedRequest{
				Item: &pb.Worker{
					ScopeId: scope.Global.String(),
					CanonicalTags: map[string]*structpb.ListValue{
						"invalid": {Values: []*structpb.Value{
							structpb.NewStringValue("invalid-canonical-tags"),
						}},
					},
				},
			},
			wantErr:         true,
			wantErrIs:       handlers.ApiErrorWithCode(codes.InvalidArgument),
			wantErrContains: globals.CanonicalTagsField,
		},
		{
			name:    "invalid-last-status-time",
			service: testSrv,
			scopeId: scope.Global.String(),
			req: &pbs.CreateControllerLedRequest{
				Item: &pb.Worker{
					ScopeId:        scope.Global.String(),
					LastStatusTime: timestamppb.Now(),
				},
			},
			wantErr:         true,
			wantErrIs:       handlers.ApiErrorWithCode(codes.InvalidArgument),
			wantErrContains: globals.LastStatusTimeField,
		},
		{
			name:    "invalid-authorized-actions",
			service: testSrv,
			scopeId: scope.Global.String(),
			req: &pbs.CreateControllerLedRequest{
				Item: &pb.Worker{
					ScopeId:           scope.Global.String(),
					AuthorizedActions: []string{"invalid-authorized-actions"},
				},
			},
			wantErr:         true,
			wantErrIs:       handlers.ApiErrorWithCode(codes.InvalidArgument),
			wantErrContains: globals.AuthorizedActionsField,
		},
		{
			name:    "invalid-create-time",
			service: testSrv,
			scopeId: scope.Global.String(),
			req: &pbs.CreateControllerLedRequest{
				Item: &pb.Worker{
					ScopeId:     scope.Global.String(),
					CreatedTime: timestamppb.Now(),
				},
			},
			wantErr:         true,
			wantErrIs:       handlers.ApiErrorWithCode(codes.InvalidArgument),
			wantErrContains: globals.CreatedTimeField,
		},
		{
			name:    "invalid-update-time",
			service: testSrv,
			scopeId: scope.Global.String(),
			req: &pbs.CreateControllerLedRequest{
				Item: &pb.Worker{
					ScopeId:     scope.Global.String(),
					UpdatedTime: timestamppb.Now(),
				},
			},
			wantErr:         true,
			wantErrIs:       handlers.ApiErrorWithCode(codes.InvalidArgument),
			wantErrContains: globals.UpdatedTimeField,
		},
		{
			name:    "invalid-version",
			service: testSrv,
			scopeId: scope.Global.String(),
			req: &pbs.CreateControllerLedRequest{
				Item: &pb.Worker{
					ScopeId: scope.Global.String(),
					Version: 1,
				},
			},
			wantErr:         true,
			wantErrIs:       handlers.ApiErrorWithCode(codes.InvalidArgument),
			wantErrContains: globals.VersionField,
		},
		{
			name:    "invalid-auth",
			service: testSrv,
			scopeId: "splat-auth-scope",
			req: &pbs.CreateControllerLedRequest{
				Item: &pb.Worker{
					ScopeId: scope.Global.String(),
				},
			},
			wantErr:         true,
			wantErrContains: "non-existent scope \"splat-auth-scope\"",
		},
		{
			name: "create-error",
			service: func() Service {
				repoFn := func() (*server.Repository, error) {
					return server.NewRepository(testCtx, rw, &db.Db{}, testKms)
				}
				testSrv, err := NewService(testCtx, repoFn, iamRepoFn, authRepoFn, nil)
				require.NoError(t, err, "Error when getting new worker service.")
				return testSrv
			}(),
			scopeId: scope.Global.String(),
			req: &pbs.CreateControllerLedRequest{
				Item: &pb.Worker{
					ScopeId:     scope.Global.String(),
					Name:        &wrapperspb.StringValue{Value: "success"},
					Description: &wrapperspb.StringValue{Value: "success-description"},
				},
			},
			wantErr:         true,
			wantErrContains: "error creating worker",
		},
		{
			name: "bad-repo-function-in-create",
			service: func() Service {
				// var cnt gives us a way for the repoFn to fail the 2nd time
				// it's called so we can get past the AuthRequest check in
				// CreateWorker(...) and test the createInRepo(...) failure
				// path if the repoFn returns and err.
				cnt := 0
				repoFn := func() (*server.Repository, error) {
					cnt = cnt + 1
					switch {
					case cnt > 1:
						return nil, errors.New(testCtx, errors.Internal, "bad-repo-function", "error creating repo")
					default:
						return server.NewRepository(testCtx, rw, rw, testKms)
					}
				}
				testSrv, err := NewService(testCtx, repoFn, iamRepoFn, authRepoFn, nil)
				require.NoError(t, err, "Error when getting new worker service.")
				return testSrv
			}(),
			scopeId: scope.Global.String(),
			req: &pbs.CreateControllerLedRequest{
				Item: &pb.Worker{
					ScopeId:     scope.Global.String(),
					Name:        &wrapperspb.StringValue{Value: "success"},
					Description: &wrapperspb.StringValue{Value: "success-description"},
				},
			},
			wantErr:         true,
			wantErrContains: "error creating worker: bad-repo-function: error creating repo",
		},
		{
			name:    "success",
			service: testSrv,
			scopeId: scope.Global.String(),
			req: &pbs.CreateControllerLedRequest{
				Item: &pb.Worker{
					ScopeId:     scope.Global.String(),
					Name:        &wrapperspb.StringValue{Value: "success"},
					Description: &wrapperspb.StringValue{Value: "success-description"},
				},
			},
			res: &pbs.CreateControllerLedResponse{
				Item: &pb.Worker{
					ScopeId:               scope.Global.String(),
					Name:                  &wrapperspb.StringValue{Value: "success"},
					Description:           &wrapperspb.StringValue{Value: "success-description"},
					ActiveConnectionCount: &wrapperspb.UInt32Value{Value: 0},
					Version:               1,
					Type:                  PkiWorkerType,
				},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := tc.service.CreateControllerLed(auth.DisabledAuthTestContext(iamRepoFn, tc.scopeId), tc.req)
			if tc.wantErr {
				require.Error(err)
				assert.Nil(got)
				if tc.wantErrIs != nil {
					assert.ErrorIs(err, tc.wantErrIs)
				}
				if tc.wantErrContains != "" {
					assert.Contains(err.Error(), tc.wantErrContains)
				}
				return
			}
			require.NoError(err)
			require.NotNil(got)
			{
				// we only need to check that these "read-only" fields were set
				// outbound. Other portions of the domain is responsible for
				// testing that these values are correct and there's no reason
				// to repeat those tests here.
				assert.NotEmpty(got.GetItem().GetId())
				assert.NotEmpty(got.GetItem().CreatedTime)
				assert.NotEmpty(got.GetItem().UpdatedTime)
				assert.NotEmpty(got.GetItem().Scope)
				assert.NotEmpty(got.GetItem().AuthorizedActions)
				assert.NotEmpty(got.GetItem().ControllerGeneratedActivationToken)
				assert.True(strings.HasPrefix(got.GetItem().ControllerGeneratedActivationToken.GetValue(), nodeenrollment.ServerLedActivationTokenPrefix))
				{
					tc.res.Item.Id = got.GetItem().GetId()
					tc.res.Item.CreatedTime = got.GetItem().GetCreatedTime()
					tc.res.Item.UpdatedTime = got.GetItem().GetUpdatedTime()
					tc.res.Item.Scope = got.GetItem().Scope
					tc.res.Item.AuthorizedActions = got.GetItem().GetAuthorizedActions()
					tc.res.Item.ControllerGeneratedActivationToken = got.GetItem().GetControllerGeneratedActivationToken()
					tc.res.Item.LocalStorageState = got.GetItem().GetLocalStorageState()
					tc.res.Item.DirectlyConnectedDownstreamWorkers = got.GetItem().GetDirectlyConnectedDownstreamWorkers()
				}
			}
			assert.Equal(tc.res, got)
		})
	}
}

func TestService_AddWorkerTags(t *testing.T) {
	ctx := context.Background()
	assert, require := assert.New(t), require.New(t)

	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	_, proj := iam.TestScopes(t, iamRepo)
	rw := db.New(conn)
	testKms := kms.TestKms(t, conn, wrapper)
	repoFn := func() (*server.Repository, error) {
		return server.NewRepository(ctx, rw, rw, testKms)
	}
	workerAuthRepo, err := server.NewRepositoryStorage(ctx, rw, rw, testKms)
	require.NoError(err)
	workerAuthRepoFn := func() (*server.WorkerAuthRepositoryStorage, error) {
		return workerAuthRepo, nil
	}
	s, err := NewService(context.Background(), repoFn, iamRepoFn, workerAuthRepoFn, nil)
	require.NoError(err)
	worker := server.TestKmsWorker(t, conn, wrapper)

	tests := []struct {
		name            string
		req             *pbs.AddWorkerTagsRequest
		wantTags        map[string]*structpb.ListValue
		wantErrContains string
	}{
		{
			name: "bad-id",
			req: &pbs.AddWorkerTagsRequest{
				Id:      "bad_id",
				Version: worker.Version,
				ApiTags: map[string]*structpb.ListValue{"key": {Values: []*structpb.Value{structpb.NewStringValue("value")}}},
			},
			wantErrContains: "Incorrectly formatted identifier.",
		},
		{
			name: "nil-version",
			req: &pbs.AddWorkerTagsRequest{
				Id:      worker.PublicId,
				ApiTags: map[string]*structpb.ListValue{"key": {Values: []*structpb.Value{structpb.NewStringValue("value")}}},
			},
			wantErrContains: "Required field.",
		},
		{
			name: "nil-tags",
			req: &pbs.AddWorkerTagsRequest{
				Id:      worker.PublicId,
				Version: worker.Version,
			},
			wantErrContains: "Must be non-empty.",
		},
		{
			name: "valid-tags",
			req: &pbs.AddWorkerTagsRequest{
				Id:      worker.PublicId,
				Version: worker.Version,
				ApiTags: map[string]*structpb.ListValue{"key": {Values: []*structpb.Value{structpb.NewStringValue("value")}}},
			},
			wantTags: map[string]*structpb.ListValue{"key": {Values: []*structpb.Value{structpb.NewStringValue("value")}}},
		},
		{
			name: "many-valid-tags",
			req: func() *pbs.AddWorkerTagsRequest {
				worker := server.TestKmsWorker(t, conn, wrapper)
				return &pbs.AddWorkerTagsRequest{
					Id:      worker.PublicId,
					Version: worker.Version,
					ApiTags: map[string]*structpb.ListValue{
						"key":  {Values: []*structpb.Value{structpb.NewStringValue("value"), structpb.NewStringValue("value2")}},
						"key2": {Values: []*structpb.Value{structpb.NewStringValue("value2")}},
						"key3": {Values: []*structpb.Value{structpb.NewStringValue("value3")}},
						"key4": {Values: []*structpb.Value{structpb.NewStringValue("value4")}},
					},
				}
			}(),
			wantTags: map[string]*structpb.ListValue{
				"key":  {Values: []*structpb.Value{structpb.NewStringValue("value"), structpb.NewStringValue("value2")}},
				"key2": {Values: []*structpb.Value{structpb.NewStringValue("value2")}},
				"key3": {Values: []*structpb.Value{structpb.NewStringValue("value3")}},
				"key4": {Values: []*structpb.Value{structpb.NewStringValue("value4")}},
			},
		},
		{
			name: "invalid-tag-value",
			req: func() *pbs.AddWorkerTagsRequest {
				worker := server.TestKmsWorker(t, conn, wrapper)
				return &pbs.AddWorkerTagsRequest{
					Id:      worker.PublicId,
					Version: worker.Version,
					ApiTags: map[string]*structpb.ListValue{"key": {Values: []*structpb.Value{structpb.NewBoolValue(false)}}},
				}
			}(),
			wantErrContains: "Tag values must be strings.",
		},
		{
			name: "invalid-managed-tag-value",
			req: func() *pbs.AddWorkerTagsRequest {
				worker := server.TestKmsWorker(t, conn, wrapper)
				return &pbs.AddWorkerTagsRequest{
					Id:      worker.PublicId,
					Version: worker.Version,
					ApiTags: map[string]*structpb.ListValue{server.ManagedWorkerTag: {Values: []*structpb.Value{structpb.NewStringValue("value2")}}},
				}
			}(),
			wantErrContains: "Tag keys cannot be the managed worker tag.",
		},
		{
			name: "mixed-invalid-tags",
			req: func() *pbs.AddWorkerTagsRequest {
				worker := server.TestKmsWorker(t, conn, wrapper)
				return &pbs.AddWorkerTagsRequest{
					Id:      worker.PublicId,
					Version: worker.Version,
					ApiTags: map[string]*structpb.ListValue{
						"":     {Values: nil},
						"key2": {Values: []*structpb.Value{structpb.NewStringValue("value2")}},
						"key3": {Values: []*structpb.Value{nil}},
						"key4": {Values: []*structpb.Value{structpb.NewStringValue("value4")}},
					},
				}
			}(),
			wantErrContains: "Tag keys must be non-empty.",
		},
		{
			name: "duplicate-tags",
			req: func() *pbs.AddWorkerTagsRequest {
				worker := server.TestKmsWorker(t, conn, wrapper)
				return &pbs.AddWorkerTagsRequest{
					Id:      worker.PublicId,
					Version: worker.Version,
					ApiTags: map[string]*structpb.ListValue{
						"key2": {Values: []*structpb.Value{structpb.NewStringValue("value2"), structpb.NewStringValue("value2")}},
						"key3": {Values: []*structpb.Value{structpb.NewStringValue("value3")}},
						"key4": {Values: []*structpb.Value{structpb.NewStringValue("value4")}},
					},
				}
			}(),
			wantErrContains: "Unable to add worker tags in repo",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := s.AddWorkerTags(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId()), tc.req)
			if len(tc.wantErrContains) > 0 {
				assert.Nil(got)
				assert.Contains(err.Error(), tc.wantErrContains)
			}
			if tc.wantTags != nil {
				assert.Nil(err)
				assert.True(equalTags(t, tc.wantTags, got.GetItem().GetApiTags()), "want tags: %q got: %q", tc.wantTags, got.GetItem().GetApiTags())
				assert.Equal(tc.req.Version+1, got.GetItem().GetVersion())
			}
		})
	}
}

func TestService_SetWorkerTags(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	_, proj := iam.TestScopes(t, iamRepo)
	rw := db.New(conn)
	testKms := kms.TestKms(t, conn, wrapper)
	repoFn := func() (*server.Repository, error) {
		return server.NewRepository(ctx, rw, rw, testKms)
	}
	workerAuthRepo, err := server.NewRepositoryStorage(ctx, rw, rw, testKms)
	require.NoError(err)
	workerAuthRepoFn := func() (*server.WorkerAuthRepositoryStorage, error) {
		return workerAuthRepo, nil
	}
	s, err := NewService(context.Background(), repoFn, iamRepoFn, workerAuthRepoFn, nil)
	require.NoError(err)
	worker := server.TestKmsWorker(t, conn, wrapper)

	tests := []struct {
		name            string
		req             *pbs.SetWorkerTagsRequest
		wantTags        map[string]*structpb.ListValue
		wantErrContains string
	}{
		{
			name: "bad-id",
			req: &pbs.SetWorkerTagsRequest{
				Id:      "bad_id",
				Version: worker.Version,
				ApiTags: map[string]*structpb.ListValue{"key": {Values: []*structpb.Value{structpb.NewStringValue("value")}}},
			},
			wantErrContains: "Incorrectly formatted identifier.",
		},
		{
			name: "nil-version",
			req: &pbs.SetWorkerTagsRequest{
				Id:      worker.PublicId,
				ApiTags: map[string]*structpb.ListValue{"key": {Values: []*structpb.Value{structpb.NewStringValue("value")}}},
			},
			wantErrContains: "Required field.",
		},
		{
			name: "nil-tags",
			req: &pbs.SetWorkerTagsRequest{
				Id:      worker.PublicId,
				Version: worker.Version,
			},
			wantTags: map[string]*structpb.ListValue{},
		},
		{
			name: "valid-tags",
			req: func() *pbs.SetWorkerTagsRequest {
				worker := server.TestKmsWorker(t, conn, wrapper)
				return &pbs.SetWorkerTagsRequest{
					Id:      worker.PublicId,
					Version: worker.Version,
					ApiTags: map[string]*structpb.ListValue{"key": {Values: []*structpb.Value{structpb.NewStringValue("value")}}},
				}
			}(),
			wantTags: map[string]*structpb.ListValue{"key": {Values: []*structpb.Value{structpb.NewStringValue("value")}}},
		},
		{
			name: "many-valid-tags",
			req: func() *pbs.SetWorkerTagsRequest {
				worker := server.TestKmsWorker(t, conn, wrapper)
				return &pbs.SetWorkerTagsRequest{
					Id:      worker.PublicId,
					Version: worker.Version,
					ApiTags: map[string]*structpb.ListValue{
						"key":  {Values: []*structpb.Value{structpb.NewStringValue("value"), structpb.NewStringValue("value2")}},
						"key2": {Values: []*structpb.Value{structpb.NewStringValue("value2")}},
						"key3": {Values: []*structpb.Value{structpb.NewStringValue("value3")}},
						"key4": {Values: []*structpb.Value{structpb.NewStringValue("value4")}},
					},
				}
			}(),
			wantTags: map[string]*structpb.ListValue{
				"key":  {Values: []*structpb.Value{structpb.NewStringValue("value"), structpb.NewStringValue("value2")}},
				"key2": {Values: []*structpb.Value{structpb.NewStringValue("value2")}},
				"key3": {Values: []*structpb.Value{structpb.NewStringValue("value3")}},
				"key4": {Values: []*structpb.Value{structpb.NewStringValue("value4")}},
			},
		},
		{
			name: "invalid-tag-value",
			req: func() *pbs.SetWorkerTagsRequest {
				worker := server.TestKmsWorker(t, conn, wrapper)
				return &pbs.SetWorkerTagsRequest{
					Id:      worker.PublicId,
					Version: worker.Version,
					ApiTags: map[string]*structpb.ListValue{"key": {Values: []*structpb.Value{structpb.NewBoolValue(false)}}},
				}
			}(),
			wantErrContains: "Tag values must be strings.",
		},
		{
			name: "invalid-managed-tag-value",
			req: func() *pbs.SetWorkerTagsRequest {
				worker := server.TestKmsWorker(t, conn, wrapper)
				return &pbs.SetWorkerTagsRequest{
					Id:      worker.PublicId,
					Version: worker.Version,
					ApiTags: map[string]*structpb.ListValue{server.ManagedWorkerTag: {Values: []*structpb.Value{structpb.NewStringValue("value2")}}},
				}
			}(),
			wantErrContains: "Tag keys cannot be the managed worker tag.",
		},
		{
			name: "mixed-invalid-tags",
			req: func() *pbs.SetWorkerTagsRequest {
				worker := server.TestKmsWorker(t, conn, wrapper)
				return &pbs.SetWorkerTagsRequest{
					Id:      worker.PublicId,
					Version: worker.Version,
					ApiTags: map[string]*structpb.ListValue{
						"key":  {Values: nil},
						"key2": {Values: []*structpb.Value{structpb.NewStringValue("value2")}},
						"key3": {Values: []*structpb.Value{structpb.NewStringValue("value3")}},
						"key4": {Values: []*structpb.Value{structpb.NewStringValue("value4")}},
					},
				}
			}(),
			wantErrContains: "Tag values must be non-empty.",
		},
		{
			name: "duplicate-tags",
			req: func() *pbs.SetWorkerTagsRequest {
				worker := server.TestKmsWorker(t, conn, wrapper)
				return &pbs.SetWorkerTagsRequest{
					Id:      worker.PublicId,
					Version: worker.Version,
					ApiTags: map[string]*structpb.ListValue{
						"key2": {Values: []*structpb.Value{structpb.NewStringValue("value2"), structpb.NewStringValue("value2")}},
						"key3": {Values: []*structpb.Value{structpb.NewStringValue("value3")}},
						"key4": {Values: []*structpb.Value{structpb.NewStringValue("value4")}},
					},
				}
			}(),
			wantErrContains: "Unable to set worker tags in repo",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := s.SetWorkerTags(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId()), tc.req)
			if len(tc.wantErrContains) > 0 {
				assert.Nil(got)
				assert.Contains(err.Error(), tc.wantErrContains)
			}
			if tc.wantTags != nil {
				assert.Nil(err)
				assert.True(equalTags(t, tc.wantTags, got.GetItem().GetApiTags()))
				assert.Equal(tc.req.Version+1, got.GetItem().GetVersion())
			}
		})
	}
}

func TestService_RemoveWorkerTags(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	_, proj := iam.TestScopes(t, iamRepo)
	rw := db.New(conn)
	testKms := kms.TestKms(t, conn, wrapper)
	repoFn := func() (*server.Repository, error) {
		return server.NewRepository(ctx, rw, rw, testKms)
	}
	workerAuthRepo, err := server.NewRepositoryStorage(ctx, rw, rw, testKms)
	require.NoError(err)
	workerAuthRepoFn := func() (*server.WorkerAuthRepositoryStorage, error) {
		return workerAuthRepo, nil
	}
	s, err := NewService(context.Background(), repoFn, iamRepoFn, workerAuthRepoFn, nil)
	require.NoError(err)
	worker := server.TestKmsWorker(t, conn, wrapper)

	tests := []struct {
		name            string
		req             *pbs.RemoveWorkerTagsRequest
		wantDeletedTags map[string]*structpb.ListValue
		wantErrContains string
	}{
		{
			name: "bad-id",
			req: &pbs.RemoveWorkerTagsRequest{
				Id:      "bad_id",
				Version: worker.Version,
				ApiTags: map[string]*structpb.ListValue{"key": {Values: []*structpb.Value{structpb.NewStringValue("value")}}},
			},
			wantErrContains: "Incorrectly formatted identifier.",
		},
		{
			name: "nil-version",
			req: &pbs.RemoveWorkerTagsRequest{
				Id:      worker.PublicId,
				ApiTags: map[string]*structpb.ListValue{"key": {Values: []*structpb.Value{structpb.NewStringValue("value")}}},
			},
			wantErrContains: "Required field.",
		},
		{
			name: "nil-tags",
			req: &pbs.RemoveWorkerTagsRequest{
				Id:      worker.PublicId,
				Version: worker.Version,
			},
			wantErrContains: "Must be non-empty.",
		},
		{
			name: "remove-valid-tag",
			req: func() *pbs.RemoveWorkerTagsRequest {
				worker := server.TestKmsWorker(t, conn, wrapper)
				_, err := s.addTagsInRepo(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId()), worker.PublicId,
					worker.Version, map[string]*structpb.ListValue{"key": {Values: []*structpb.Value{structpb.NewStringValue("value")}}})
				require.NoError(err)
				return &pbs.RemoveWorkerTagsRequest{
					Id:      worker.PublicId,
					Version: worker.Version + 1,
					ApiTags: map[string]*structpb.ListValue{"key": {Values: []*structpb.Value{structpb.NewStringValue("value")}}},
				}
			}(),
			wantDeletedTags: map[string]*structpb.ListValue{"key": {Values: []*structpb.Value{structpb.NewStringValue("value")}}},
		},
		{
			name: "remove-many-valid-tags",
			req: func() *pbs.RemoveWorkerTagsRequest {
				worker := server.TestKmsWorker(t, conn, wrapper)
				_, err := s.addTagsInRepo(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId()), worker.PublicId,
					worker.Version, map[string]*structpb.ListValue{
						"key":  {Values: []*structpb.Value{structpb.NewStringValue("value"), structpb.NewStringValue("value1")}},
						"key2": {Values: []*structpb.Value{structpb.NewStringValue("value2")}},
						"key3": {Values: []*structpb.Value{structpb.NewStringValue("value")}},
						"key4": {Values: []*structpb.Value{structpb.NewStringValue("value4")}},
						"key5": {Values: []*structpb.Value{structpb.NewStringValue("value5")}},
						"key6": {Values: []*structpb.Value{structpb.NewStringValue("value")}},
					})
				require.NoError(err)
				return &pbs.RemoveWorkerTagsRequest{
					Id:      worker.PublicId,
					Version: worker.Version + 1,
					ApiTags: map[string]*structpb.ListValue{
						"key":  {Values: []*structpb.Value{structpb.NewStringValue("value"), structpb.NewStringValue("value1")}},
						"key2": {Values: []*structpb.Value{structpb.NewStringValue("value2")}},
						"key3": {Values: []*structpb.Value{structpb.NewStringValue("value")}},
						"key4": {Values: []*structpb.Value{structpb.NewStringValue("value4")}},
						"key5": {Values: []*structpb.Value{structpb.NewStringValue("value5")}},
						"key6": {Values: []*structpb.Value{structpb.NewStringValue("value")}},
					},
				}
			}(),
			wantDeletedTags: map[string]*structpb.ListValue{
				"key":  {Values: []*structpb.Value{structpb.NewStringValue("value")}},
				"key2": {Values: []*structpb.Value{structpb.NewStringValue("value2")}},
				"key3": {Values: []*structpb.Value{structpb.NewStringValue("value")}},
				"key4": {Values: []*structpb.Value{structpb.NewStringValue("value4")}},
				"key5": {Values: []*structpb.Value{structpb.NewStringValue("value5")}},
				"key6": {Values: []*structpb.Value{structpb.NewStringValue("value")}},
			},
		},
		{
			name: "invalid-tag-value",
			req: func() *pbs.RemoveWorkerTagsRequest {
				worker := server.TestKmsWorker(t, conn, wrapper)
				return &pbs.RemoveWorkerTagsRequest{
					Id:      worker.PublicId,
					Version: worker.Version,
					ApiTags: map[string]*structpb.ListValue{"key": {Values: []*structpb.Value{structpb.NewBoolValue(false)}}},
				}
			}(),
			wantErrContains: "Tag values must be strings.",
		},
		{
			name: "mixed-invalid-tags",
			req: func() *pbs.RemoveWorkerTagsRequest {
				worker := server.TestKmsWorker(t, conn, wrapper)
				return &pbs.RemoveWorkerTagsRequest{
					Id:      worker.PublicId,
					Version: worker.Version,
					ApiTags: map[string]*structpb.ListValue{
						"key":  {Values: nil},
						"key2": {Values: []*structpb.Value{structpb.NewStringValue("value2")}},
					},
				}
			}(),
			wantErrContains: "Tag values must be non-empty.",
		},
		{
			name: "remove-nonexistent-tags",
			req: func() *pbs.RemoveWorkerTagsRequest {
				worker := server.TestKmsWorker(t, conn, wrapper)
				_, err := s.addTagsInRepo(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId()), worker.PublicId,
					worker.Version, map[string]*structpb.ListValue{
						"key":  {Values: []*structpb.Value{structpb.NewStringValue("value")}},
						"key2": {Values: []*structpb.Value{structpb.NewStringValue("value2")}},
						"key3": {Values: []*structpb.Value{structpb.NewStringValue("value")}},
						"key4": {Values: []*structpb.Value{structpb.NewStringValue("value4")}},
						"key5": {Values: []*structpb.Value{structpb.NewStringValue("value5")}},
						"key6": {Values: []*structpb.Value{structpb.NewStringValue("value")}},
					})
				require.NoError(err)
				return &pbs.RemoveWorkerTagsRequest{
					Id:      worker.PublicId,
					Version: worker.Version + 1,
					ApiTags: map[string]*structpb.ListValue{
						"no-key": {Values: []*structpb.Value{structpb.NewStringValue("value")}},
						"key2":   {Values: []*structpb.Value{structpb.NewStringValue("value2")}},
						"key":    {Values: []*structpb.Value{structpb.NewStringValue("value")}},
					},
				}
			}(),
			wantErrContains: "Unable to remove worker tags in repo:",
		},
		{
			name: "duplicate-tags",
			req: func() *pbs.RemoveWorkerTagsRequest {
				worker := server.TestKmsWorker(t, conn, wrapper)
				return &pbs.RemoveWorkerTagsRequest{
					Id:      worker.PublicId,
					Version: worker.Version,
					ApiTags: map[string]*structpb.ListValue{
						"key2": {Values: []*structpb.Value{structpb.NewStringValue("value2"), structpb.NewStringValue("value2")}},
						"key3": {Values: []*structpb.Value{structpb.NewStringValue("value3")}},
						"key4": {Values: []*structpb.Value{structpb.NewStringValue("value4")}},
					},
				}
			}(),
			wantErrContains: "Unable to remove worker tags in repo",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := s.RemoveWorkerTags(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId()), tc.req)
			if len(tc.wantErrContains) > 0 {
				assert.Nil(got)
				assert.Contains(err.Error(), tc.wantErrContains)
			}
			if tc.wantDeletedTags != nil {
				assert.Nil(err)
				assert.False(equalTags(t, tc.wantDeletedTags, got.GetItem().GetApiTags()))
				assert.Equal(tc.req.Version+1, got.GetItem().GetVersion())
			}
		})
	}
}

func TestReadCertificateAuthority(t *testing.T) {
	require, assert := require.New(t), assert.New(t)
	ctx := context.Background()
	wrapper := db.TestWrapper(t)
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	kmsCache := kms.TestKms(t, conn, wrapper)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}

	repoFn := func() (*server.Repository, error) {
		return server.NewRepository(ctx, rw, rw, kmsCache)
	}

	workerAuthRepo, err := server.NewRepositoryStorage(ctx, rw, rw, kmsCache)
	require.NoError(err)
	workerAuthRepoFn := func() (*server.WorkerAuthRepositoryStorage, error) {
		return workerAuthRepo, nil
	}

	// Store CA and check that initial version updates
	_, err = rotation.RotateRootCertificates(ctx, workerAuthRepo)
	require.NoError(err)

	testSrv, err := NewService(ctx, repoFn, iamRepoFn, workerAuthRepoFn, nil)
	require.NoError(err, "Error when getting new worker service.")

	tests := []struct {
		name            string
		scopeId         string
		req             *pbs.ReadCertificateAuthorityRequest
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name:    "invalid-scope",
			scopeId: scope.Global.String(),
			req: &pbs.ReadCertificateAuthorityRequest{
				ScopeId: "invalid-scope",
			},
			wantErr:         true,
			wantErrIs:       handlers.ApiErrorWithCode(codes.InvalidArgument),
			wantErrContains: "Must be 'global'",
		},
		{
			name:    "success",
			scopeId: scope.Global.String(),
			req: &pbs.ReadCertificateAuthorityRequest{
				ScopeId: "global",
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := testSrv.ReadCertificateAuthority(auth.DisabledAuthTestContext(iamRepoFn, tc.scopeId), tc.req)
			if tc.wantErr {
				require.Error(err)
				assert.Nil(got)
				if tc.wantErrIs != nil {
					assert.ErrorIs(err, tc.wantErrIs)
				}
				if tc.wantErrContains != "" {
					assert.Contains(err.Error(), tc.wantErrContains)
				}
				return
			}
			require.NoError(err)
			require.NotNil(got)
		})
	}
}

func TestReinitializeCertificateAuthority(t *testing.T) {
	require, assert := require.New(t), assert.New(t)
	ctx := context.Background()
	wrapper := db.TestWrapper(t)
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	kmsCache := kms.TestKms(t, conn, wrapper)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}

	repoFn := func() (*server.Repository, error) {
		return server.NewRepository(ctx, rw, rw, kmsCache)
	}

	workerAuthRepo, err := server.NewRepositoryStorage(ctx, rw, rw, kmsCache)
	require.NoError(err)
	workerAuthRepoFn := func() (*server.WorkerAuthRepositoryStorage, error) {
		return workerAuthRepo, nil
	}

	// Store CA and check that initial version updates
	_, err = rotation.RotateRootCertificates(ctx, workerAuthRepo)
	require.NoError(err)

	testSrv, err := NewService(ctx, repoFn, iamRepoFn, workerAuthRepoFn, nil)
	require.NoError(err, "Error when getting new worker service.")

	tests := []struct {
		name            string
		scopeId         string
		req             *pbs.ReinitializeCertificateAuthorityRequest
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name:    "invalid-id",
			scopeId: scope.Global.String(),
			req: &pbs.ReinitializeCertificateAuthorityRequest{
				ScopeId: "bogus",
			},
			wantErr:         true,
			wantErrIs:       handlers.ApiErrorWithCode(codes.InvalidArgument),
			wantErrContains: "Must be 'global'",
		},
		{
			name:    "success",
			scopeId: scope.Global.String(),
			req: &pbs.ReinitializeCertificateAuthorityRequest{
				ScopeId: "global",
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := testSrv.ReinitializeCertificateAuthority(auth.DisabledAuthTestContext(iamRepoFn, tc.scopeId), tc.req)
			if tc.wantErr {
				require.Error(err)
				assert.Nil(got)
				if tc.wantErrIs != nil {
					assert.ErrorIs(err, tc.wantErrIs)
				}
				if tc.wantErrContains != "" {
					assert.Contains(err.Error(), tc.wantErrContains)
				}
				return
			}
			require.NoError(err)
			require.NotNil(got)
		})
	}
}

func Test_RemoteStorageStatesToMapProto(t *testing.T) {
	t.Parallel()
	testTime := timestamppb.New(time.Now().UTC().Round(time.Second))
	tests := []struct {
		name           string
		input          map[string]*plugin.StorageBucketCredentialState
		expectedErrMsg string
		expectedOutput map[string]*pb.RemoteStorageState
	}{
		{
			name:           "nil",
			expectedOutput: map[string]*pb.RemoteStorageState{},
		},
		{
			name:           "empty",
			expectedOutput: map[string]*pb.RemoteStorageState{},
		},
		{
			name: "available",
			input: map[string]*plugin.StorageBucketCredentialState{
				"sb_1234567890": {
					State: &plugin.Permissions{
						Write: &plugin.Permission{
							State:     plugin.StateType_STATE_TYPE_OK,
							CheckedAt: testTime,
						},
						Read: &plugin.Permission{
							State:     plugin.StateType_STATE_TYPE_OK,
							CheckedAt: testTime,
						},
						Delete: &plugin.Permission{
							State:     plugin.StateType_STATE_TYPE_OK,
							CheckedAt: testTime,
						},
					},
					Version: 1,
				},
			},
			expectedOutput: map[string]*pb.RemoteStorageState{
				"sb_1234567890": {
					Status: "available",
					Permissions: &pb.RemoteStoragePermissions{
						Write:  "ok",
						Read:   "ok",
						Delete: "ok",
					},
				},
			},
		},
		{
			name: "write error",
			input: map[string]*plugin.StorageBucketCredentialState{
				"sb_1234567890": {
					State: &plugin.Permissions{
						Write: &plugin.Permission{
							State:        plugin.StateType_STATE_TYPE_ERROR,
							ErrorDetails: "invalid credentials",
							CheckedAt:    testTime,
						},
						Read: &plugin.Permission{
							State:     plugin.StateType_STATE_TYPE_OK,
							CheckedAt: testTime,
						},
						Delete: &plugin.Permission{
							State:     plugin.StateType_STATE_TYPE_OK,
							CheckedAt: testTime,
						},
					},
					Version: 1,
				},
			},
			expectedOutput: map[string]*pb.RemoteStorageState{
				"sb_1234567890": {
					Status: "error",
					Permissions: &pb.RemoteStoragePermissions{
						Write:  "error",
						Read:   "ok",
						Delete: "ok",
					},
				},
			},
		},
		{
			name: "read error",
			input: map[string]*plugin.StorageBucketCredentialState{
				"sb_1234567890": {
					State: &plugin.Permissions{
						Write: &plugin.Permission{
							State:     plugin.StateType_STATE_TYPE_OK,
							CheckedAt: testTime,
						},
						Read: &plugin.Permission{
							State:        plugin.StateType_STATE_TYPE_ERROR,
							ErrorDetails: "invalid credentials",
							CheckedAt:    testTime,
						},
						Delete: &plugin.Permission{
							State:     plugin.StateType_STATE_TYPE_OK,
							CheckedAt: testTime,
						},
					},
					Version: 1,
				},
			},
			expectedOutput: map[string]*pb.RemoteStorageState{
				"sb_1234567890": {
					Status: "error",
					Permissions: &pb.RemoteStoragePermissions{
						Write:  "ok",
						Read:   "error",
						Delete: "ok",
					},
				},
			},
		},
		{
			name: "delete error",
			input: map[string]*plugin.StorageBucketCredentialState{
				"sb_1234567890": {
					State: &plugin.Permissions{
						Write: &plugin.Permission{
							State:     plugin.StateType_STATE_TYPE_OK,
							CheckedAt: testTime,
						},
						Read: &plugin.Permission{
							State:     plugin.StateType_STATE_TYPE_OK,
							CheckedAt: testTime,
						},
						Delete: &plugin.Permission{
							State:        plugin.StateType_STATE_TYPE_ERROR,
							ErrorDetails: "invalid credentials",
							CheckedAt:    testTime,
						},
					},
					Version: 1,
				},
			},
			expectedOutput: map[string]*pb.RemoteStorageState{
				"sb_1234567890": {
					Status: "error",
					Permissions: &pb.RemoteStoragePermissions{
						Write:  "ok",
						Read:   "ok",
						Delete: "error",
					},
				},
			},
		},
		{
			name: "error",
			input: map[string]*plugin.StorageBucketCredentialState{
				"sb_1234567890": {
					State: &plugin.Permissions{
						Write: &plugin.Permission{
							State:        plugin.StateType_STATE_TYPE_ERROR,
							ErrorDetails: "invalid credentials",
							CheckedAt:    testTime,
						},
						Read: &plugin.Permission{
							State:        plugin.StateType_STATE_TYPE_ERROR,
							ErrorDetails: "invalid credentials",
							CheckedAt:    testTime,
						},
						Delete: &plugin.Permission{
							State:        plugin.StateType_STATE_TYPE_ERROR,
							ErrorDetails: "invalid credentials",
							CheckedAt:    testTime,
						},
					},
					Version: 1,
				},
			},
			expectedOutput: map[string]*pb.RemoteStorageState{
				"sb_1234567890": {
					Status: "error",
					Permissions: &pb.RemoteStoragePermissions{
						Write:  "error",
						Read:   "error",
						Delete: "error",
					},
				},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require, assert := require.New(t), assert.New(t)
			actualOutput, err := remoteStorageStatesToMapProto(tc.input)
			if tc.expectedErrMsg != "" {
				require.Error(err)
				assert.ErrorContains(err, tc.expectedErrMsg)
				assert.Nil(actualOutput)
				return
			}
			require.NoError(err)
			require.Len(actualOutput, len(tc.expectedOutput))
			for storageBucketId, expectedState := range tc.expectedOutput {
				actualState, ok := actualOutput[storageBucketId]
				require.True(ok)
				assert.Equal(expectedState.GetStatus(), actualState.GetStatus())
				assert.Equal(expectedState.GetPermissions().GetWrite(), actualState.GetPermissions().GetWrite())
				assert.Equal(expectedState.GetPermissions().GetRead(), actualState.GetPermissions().GetRead())
				assert.Equal(expectedState.GetPermissions().GetDelete(), actualState.GetPermissions().GetDelete())
			}
		})
	}
}
