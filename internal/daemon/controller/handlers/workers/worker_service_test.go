package workers

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
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
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/workers"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/workers"
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
	var val []interface{}
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
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrap)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	rw := db.New(conn)
	kms := kms.TestKms(t, conn, wrap)
	repo, err := server.NewRepository(rw, rw, kms)
	require.NoError(t, err)
	repoFn := func() (*server.Repository, error) {
		return repo, nil
	}

	kmsWorker := server.TestKmsWorker(t, conn, wrap,
		server.WithName("test kms worker names"),
		server.WithDescription("test kms worker description"),
		server.WithAddress("test kms worker address"),
		server.WithWorkerTags(&server.Tag{Key: "key", Value: "val"}))

	kmsAuthzActions := make([]string, len(testAuthorizedActions))
	copy(kmsAuthzActions, testAuthorizedActions)

	wantKmsWorker := &pb.Worker{
		Id:                    kmsWorker.GetPublicId(),
		ScopeId:               kmsWorker.GetScopeId(),
		Scope:                 &scopes.ScopeInfo{Id: kmsWorker.GetScopeId(), Type: scope.Global.String(), Name: scope.Global.String(), Description: "Global Scope"},
		CreatedTime:           kmsWorker.CreateTime.GetTimestamp(),
		UpdatedTime:           kmsWorker.UpdateTime.GetTimestamp(),
		Version:               kmsWorker.GetVersion(),
		Name:                  wrapperspb.String(kmsWorker.GetName()),
		Description:           wrapperspb.String(kmsWorker.GetDescription()),
		Address:               kmsWorker.GetAddress(),
		ActiveConnectionCount: &wrapperspb.UInt32Value{Value: 0},
		AuthorizedActions:     strutil.StrListDelete(kmsAuthzActions, action.Update.String()),
		LastStatusTime:        kmsWorker.GetLastStatusTime().GetTimestamp(),
		CanonicalTags: map[string]*structpb.ListValue{
			"key": structListValue(t, "val"),
		},
		ConfigTags: map[string]*structpb.ListValue{
			"key": structListValue(t, "val"),
		},
		Type: KmsWorkerType,
	}

	var pkiWorkerKeyId string
	pkiWorker := server.TestPkiWorker(t, conn, wrap,
		server.WithName("test pki worker names"),
		server.WithDescription("test pki worker description"),
		server.WithTestPkiWorkerAuthorizedKeyId(&pkiWorkerKeyId))
	// Add config tags to the created worker
	pkiWorker, err = repo.UpsertWorkerStatus(context.Background(),
		server.NewWorker(pkiWorker.GetScopeId(),
			server.WithAddress("test kms worker address"),
			server.WithWorkerTags(&server.Tag{
				Key:   "config",
				Value: "test",
			})),
		server.WithUpdateTags(true),
		server.WithPublicId(pkiWorker.GetPublicId()),
		server.WithKeyVersionId(pkiWorkerKeyId))
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
		CanonicalTags: map[string]*structpb.ListValue{
			"config": structListValue(t, "test"),
		},
		ConfigTags: map[string]*structpb.ListValue{
			"config": structListValue(t, "test"),
		},
		Type: PkiWorkerType,
	}

	cases := []struct {
		name    string
		scopeId string
		req     *pbs.GetWorkerRequest
		res     *pbs.GetWorkerResponse
		err     error
	}{
		{
			name:    "Get an Existing KMS Worker",
			scopeId: kmsWorker.GetScopeId(),
			req:     &pbs.GetWorkerRequest{Id: kmsWorker.GetPublicId()},
			res:     &pbs.GetWorkerResponse{Item: wantKmsWorker},
		},
		{
			name:    "Get an Existing PKI Worker",
			scopeId: pkiWorker.GetScopeId(),
			req:     &pbs.GetWorkerRequest{Id: pkiWorker.GetPublicId()},
			res:     &pbs.GetWorkerResponse{Item: wantPkiWorker},
		},
		{
			name: "Get a non-existent Worker",
			req:  &pbs.GetWorkerRequest{Id: server.WorkerPrefix + "_DoesntExis"},
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
			req:  &pbs.GetWorkerRequest{Id: server.WorkerPrefix + "_1 23456789"},
			res:  nil,
			err:  handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := NewService(context.Background(), repoFn, iamRepoFn)
			require.NoError(t, err, "Couldn't create new worker service.")

			got, err := s.GetWorker(auth.DisabledAuthTestContext(iamRepoFn, tc.scopeId), tc.req)
			if tc.err != nil {
				require.Error(t, err)
				assert.True(t, errors.Is(err, tc.err), "GetWorker(%+v) got error %v, wanted %v", tc.req, err, tc.err)
			} else {
				require.NoError(t, err)
			}
			assert.Empty(t, cmp.Diff(got, tc.res, protocmp.Transform()), "GetWorker(%q) got response\n%q, wanted\n%q", tc.req, got, tc.res)
		})
	}
}

func TestList(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrap)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	rw := db.New(conn)
	kms := kms.TestKms(t, conn, wrap)
	repoFn := func() (*server.Repository, error) {
		return server.NewRepository(rw, rw, kms)
	}

	var wantKmsWorkers []*pb.Worker
	for i := 0; i < 10; i++ {
		w := server.TestKmsWorker(t, conn, wrap, server.WithName(fmt.Sprintf("kms-worker%d", i)))
		kmsAuthzActions := make([]string, len(testAuthorizedActions))
		copy(kmsAuthzActions, testAuthorizedActions)
		wantKmsWorkers = append(wantKmsWorkers, &pb.Worker{
			Id:                    w.GetPublicId(),
			ScopeId:               w.GetScopeId(),
			Scope:                 &scopes.ScopeInfo{Id: w.GetScopeId(), Type: scope.Global.String(), Name: scope.Global.String(), Description: "Global Scope"},
			CreatedTime:           w.CreateTime.GetTimestamp(),
			UpdatedTime:           w.UpdateTime.GetTimestamp(),
			Version:               w.GetVersion(),
			Name:                  wrapperspb.String(w.GetName()),
			AuthorizedActions:     strutil.StrListDelete(kmsAuthzActions, action.Update.String()),
			ActiveConnectionCount: &wrapperspb.UInt32Value{Value: 0},
			Address:               w.GetAddress(),
			Type:                  KmsWorkerType,
			LastStatusTime:        w.GetLastStatusTime().GetTimestamp(),
		})
	}

	var wantPkiWorkers []*pb.Worker
	for i := 0; i < 10; i++ {
		w := server.TestPkiWorker(t, conn, wrap, server.WithName(fmt.Sprintf("pki-worker%d", i)))
		wantPkiWorkers = append(wantPkiWorkers, &pb.Worker{
			Id:                    w.GetPublicId(),
			ScopeId:               w.GetScopeId(),
			Scope:                 &scopes.ScopeInfo{Id: w.GetScopeId(), Type: scope.Global.String(), Name: scope.Global.String(), Description: "Global Scope"},
			CreatedTime:           w.CreateTime.GetTimestamp(),
			UpdatedTime:           w.UpdateTime.GetTimestamp(),
			Version:               w.GetVersion(),
			Name:                  wrapperspb.String(w.GetName()),
			ActiveConnectionCount: &wrapperspb.UInt32Value{Value: 0},
			AuthorizedActions:     testAuthorizedActions,
			Address:               w.GetAddress(),
			Type:                  PkiWorkerType,
			LastStatusTime:        w.GetLastStatusTime().GetTimestamp(),
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
			s, err := NewService(context.Background(), repoFn, iamRepoFn)
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
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "ListWorkers(%q) got response %q, wanted %q", tc.req.GetScopeId(), got, tc.res)

			// Test the anon case
			got, gErr = s.ListWorkers(auth.DisabledAuthTestContext(iamRepoFn, tc.req.GetScopeId(), auth.WithUserId(auth.AnonymousUserId)), tc.req)
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
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrap)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	rw := db.New(conn)
	kms := kms.TestKms(t, conn, wrap)
	repoFn := func() (*server.Repository, error) {
		return server.NewRepository(rw, rw, kms)
	}
	ctx := context.Background()

	s, err := NewService(ctx, repoFn, iamRepoFn)
	require.NoError(t, err, "Error when getting new worker service.")

	w := server.TestKmsWorker(t, conn, wrap)

	cases := []struct {
		name    string
		scopeId string
		req     *pbs.DeleteWorkerRequest
		res     *pbs.DeleteWorkerResponse
		err     error
	}{
		{
			name:    "Delete an Existing Worker",
			scopeId: w.GetScopeId(),
			req: &pbs.DeleteWorkerRequest{
				Id: w.GetPublicId(),
			},
		},
		{
			name:    "Delete bad worker id",
			scopeId: w.GetScopeId(),
			req: &pbs.DeleteWorkerRequest{
				Id: server.WorkerPrefix + "_doesntexis",
			},
			err: handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name:    "Bad Worker Id formatting",
			scopeId: w.GetScopeId(),
			req: &pbs.DeleteWorkerRequest{
				Id: "bad_format",
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
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
			assert.EqualValuesf(tc.res, got, "DeleteWorker(%+v) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestUpdate(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	ctx := context.Background()
	rw := db.New(conn)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	repo, err := server.NewRepository(rw, rw, kms)
	require.NoError(t, err)
	repoFn := func() (*server.Repository, error) {
		return repo, nil
	}

	wkr := server.TestPkiWorker(t, conn, wrapper,
		server.WithName("default"),
		server.WithDescription("default"))

	version := wkr.GetVersion()

	resetWorker := func() {
		version++
		_, _, err = repo.UpdateWorker(context.Background(), wkr, version, []string{"Name", "Description"})
		require.NoError(t, err, "Failed to reset worker.")
		version++
	}

	wCreated := wkr.GetCreateTime().GetTimestamp().AsTime()
	toMerge := &pbs.UpdateWorkerRequest{
		Id: wkr.GetPublicId(),
	}
	workerService, err := NewService(ctx, repoFn, iamRepoFn)
	require.NoError(t, err)
	expectedScope := &scopes.ScopeInfo{Id: scope.Global.String(), Type: scope.Global.String(), Name: scope.Global.String(), Description: "Global Scope"}

	cases := []struct {
		name string
		req  *pbs.UpdateWorkerRequest
		res  *pbs.UpdateWorkerResponse
		err  error
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
			res: &pbs.UpdateWorkerResponse{
				Item: &pb.Worker{
					Id:                    wkr.GetPublicId(),
					ScopeId:               wkr.GetScopeId(),
					Scope:                 expectedScope,
					Name:                  wrapperspb.String("name"),
					Description:           wrapperspb.String("desc"),
					CreatedTime:           wkr.GetCreateTime().GetTimestamp(),
					ActiveConnectionCount: &wrapperspb.UInt32Value{Value: 0},
					LastStatusTime:        wkr.GetLastStatusTime().GetTimestamp(),
					AuthorizedActions:     testAuthorizedActions,
					Type:                  PkiWorkerType,
				},
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
					Description: wrapperspb.String("desc"),
				},
			},
			res: &pbs.UpdateWorkerResponse{
				Item: &pb.Worker{
					Id:                    wkr.GetPublicId(),
					ScopeId:               wkr.GetScopeId(),
					Scope:                 expectedScope,
					Name:                  wrapperspb.String("name"),
					Description:           wrapperspb.String("desc"),
					ActiveConnectionCount: &wrapperspb.UInt32Value{Value: 0},
					CreatedTime:           wkr.GetCreateTime().GetTimestamp(),
					LastStatusTime:        wkr.GetLastStatusTime().GetTimestamp(),
					AuthorizedActions:     testAuthorizedActions,
					Type:                  PkiWorkerType,
				},
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
			name: "Only non-existant paths in Mask",
			req: &pbs.UpdateWorkerRequest{
				UpdateMask: &field_mask.FieldMask{Paths: []string{"nonexistant_field"}},
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
			res: &pbs.UpdateWorkerResponse{
				Item: &pb.Worker{
					Id:                    wkr.GetPublicId(),
					ScopeId:               wkr.GetScopeId(),
					Scope:                 expectedScope,
					Description:           wrapperspb.String("default"),
					ActiveConnectionCount: &wrapperspb.UInt32Value{Value: 0},
					CreatedTime:           wkr.GetCreateTime().GetTimestamp(),
					LastStatusTime:        wkr.GetLastStatusTime().GetTimestamp(),
					AuthorizedActions:     testAuthorizedActions,
					Type:                  PkiWorkerType,
				},
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
			res: &pbs.UpdateWorkerResponse{
				Item: &pb.Worker{
					Id:                    wkr.GetPublicId(),
					ScopeId:               wkr.GetScopeId(),
					Scope:                 expectedScope,
					Name:                  wrapperspb.String("default"),
					CreatedTime:           wkr.GetCreateTime().GetTimestamp(),
					ActiveConnectionCount: &wrapperspb.UInt32Value{Value: 0},
					LastStatusTime:        wkr.GetLastStatusTime().GetTimestamp(),
					AuthorizedActions:     testAuthorizedActions,
					Type:                  PkiWorkerType,
				},
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
			res: &pbs.UpdateWorkerResponse{
				Item: &pb.Worker{
					Id:                    wkr.GetPublicId(),
					ScopeId:               wkr.GetScopeId(),
					Scope:                 expectedScope,
					Name:                  wrapperspb.String("updated"),
					Description:           wrapperspb.String("default"),
					CreatedTime:           wkr.GetCreateTime().GetTimestamp(),
					ActiveConnectionCount: &wrapperspb.UInt32Value{Value: 0},
					LastStatusTime:        wkr.GetLastStatusTime().GetTimestamp(),
					AuthorizedActions:     testAuthorizedActions,
					Type:                  PkiWorkerType,
				},
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
			res: &pbs.UpdateWorkerResponse{
				Item: &pb.Worker{
					Id:                    wkr.GetPublicId(),
					ScopeId:               wkr.GetScopeId(),
					Scope:                 expectedScope,
					Name:                  wrapperspb.String("default"),
					ActiveConnectionCount: &wrapperspb.UInt32Value{Value: 0},
					Description:           wrapperspb.String("notignored"),
					CreatedTime:           wkr.GetCreateTime().GetTimestamp(),
					LastStatusTime:        wkr.GetLastStatusTime().GetTimestamp(),
					AuthorizedActions:     testAuthorizedActions,
					Type:                  PkiWorkerType,
				},
			},
		},
		{
			name: "Update a Non Existing Worker",
			req: &pbs.UpdateWorkerRequest{
				Id: server.WorkerPrefix + "_DoesntExis",
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
			name: "Cant change Id",
			req: &pbs.UpdateWorkerRequest{
				Id: wkr.GetPublicId(),
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
		t.Run(tc.name, func(t *testing.T) {
			tc.req.Item.Version = version

			req := proto.Clone(toMerge).(*pbs.UpdateWorkerRequest)
			proto.Merge(req, tc.req)

			got, gErr := workerService.UpdateWorker(auth.DisabledAuthTestContext(iamRepoFn, scope.Global.String()), req)
			if tc.err != nil {
				require.Error(t, gErr)
				assert.True(t, errors.Is(gErr, tc.err), "UpdateWorker(%+v) got error %v, wanted %v", req, gErr, tc.err)
			}

			if tc.err == nil {
				defer resetWorker()
			}

			if got != nil {
				assert.NotNilf(t, tc.res, "Expected UpdateWorker response to be nil, but was %v", got)
				gotUpdateTime := got.GetItem().GetUpdatedTime().AsTime()
				// Verify updated set after it was created
				assert.True(t, gotUpdateTime.After(wCreated), "Updated resource should have been updated after its creation. Was updated %v, which is after %v", gotUpdateTime, wCreated)

				// Clear all values which are hard to compare against.
				got.Item.UpdatedTime, tc.res.Item.UpdatedTime = nil, nil
			}
			if tc.res != nil {
				tc.res.Item.Version = version + 1
			}
			assert.Empty(t, cmp.Diff(got, tc.res, protocmp.Transform()), "UpdateWorker(%q) got response %q, wanted %q", req, got, tc.res)
		})
	}
}

func TestUpdate_KMS(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	ctx := context.Background()
	rw := db.New(conn)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	repo, err := server.NewRepository(rw, rw, kms)
	require.NoError(t, err)
	repoFn := func() (*server.Repository, error) {
		return repo, nil
	}

	wkr := server.TestKmsWorker(t, conn, wrapper,
		server.WithName("default"),
		server.WithDescription("default"))

	toMerge := &pbs.UpdateWorkerRequest{
		Id: wkr.GetPublicId(),
	}
	workerService, err := NewService(ctx, repoFn, iamRepoFn)
	require.NoError(t, err)

	cases := []struct {
		name string
		req  *pbs.UpdateWorkerRequest
		res  *pbs.UpdateWorkerResponse
		err  error
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
		})
	}
}

func TestUpdate_BadVersion(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}

	_, proj := iam.TestScopes(t, iamRepo)

	rw := db.New(conn)
	repo, err := server.NewRepository(rw, rw, kms)
	require.NoError(t, err, "Couldn't create new worker repo.")
	repoFn := func() (*server.Repository, error) {
		return repo, nil
	}
	ctx := context.Background()

	workerService, err := NewService(ctx, repoFn, iamRepoFn)
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
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	testRootWrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, testRootWrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	rw := db.New(conn)
	testKms := kms.TestKms(t, conn, testRootWrapper)
	repoFn := func() (*server.Repository, error) {
		return server.NewRepository(rw, rw, testKms)
	}
	testCtx := context.Background()

	testSrv, err := NewService(testCtx, repoFn, iamRepoFn)
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
		defer fileStorage.Cleanup()

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
				Item: &workers.Worker{
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
				Item: &workers.Worker{
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
				Item: &workers.Worker{
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
				Item: &workers.Worker{
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
				Item: &workers.Worker{
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
				Item: &workers.Worker{
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
				Item: &workers.Worker{
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
				Item: &workers.Worker{
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
				Item: &workers.Worker{
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
				Item: &workers.Worker{
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
				Item: &workers.Worker{
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
				Item: &workers.Worker{
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
				Item: &workers.Worker{
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
				Item: &workers.Worker{
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
					return server.NewRepository(rw, &db.Db{}, testKms)
				}
				testSrv, err := NewService(testCtx, repoFn, iamRepoFn)
				require.NoError(t, err, "Error when getting new worker service.")
				return testSrv
			}(),
			scopeId: scope.Global.String(),
			req: &pbs.CreateWorkerLedRequest{
				Item: &workers.Worker{
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
						return server.NewRepository(rw, rw, testKms)
					}
				}
				testSrv, err := NewService(testCtx, repoFn, iamRepoFn)
				require.NoError(t, err, "Error when getting new worker service.")
				return testSrv
			}(),
			scopeId: scope.Global.String(),
			req: &pbs.CreateWorkerLedRequest{
				Item: &workers.Worker{
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
				Item: &workers.Worker{
					ScopeId:                  scope.Global.String(),
					Name:                     &wrapperspb.StringValue{Value: "success"},
					Description:              &wrapperspb.StringValue{Value: "success-description"},
					WorkerGeneratedAuthToken: &wrapperspb.StringValue{Value: fetchReqFn()},
				},
			},
			res: &pbs.CreateWorkerLedResponse{
				Item: &workers.Worker{
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
				}
			}
			assert.Equal(tc.res, got)
		})
	}
}

func TestCreateControllerLed(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	testRootWrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, testRootWrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	rw := db.New(conn)
	testKms := kms.TestKms(t, conn, testRootWrapper)
	repoFn := func() (*server.Repository, error) {
		return server.NewRepository(rw, rw, testKms)
	}
	testCtx := context.Background()

	testSrv, err := NewService(testCtx, repoFn, iamRepoFn)
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
		defer fileStorage.Cleanup()

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
				Item: &workers.Worker{
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
				Item: &workers.Worker{
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
				Item: &workers.Worker{
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
				Item: &workers.Worker{
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
				Item: &workers.Worker{
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
				Item: &workers.Worker{
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
				Item: &workers.Worker{
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
				Item: &workers.Worker{
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
				Item: &workers.Worker{
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
				Item: &workers.Worker{
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
				Item: &workers.Worker{
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
				Item: &workers.Worker{
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
					return server.NewRepository(rw, &db.Db{}, testKms)
				}
				testSrv, err := NewService(testCtx, repoFn, iamRepoFn)
				require.NoError(t, err, "Error when getting new worker service.")
				return testSrv
			}(),
			scopeId: scope.Global.String(),
			req: &pbs.CreateControllerLedRequest{
				Item: &workers.Worker{
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
						return server.NewRepository(rw, rw, testKms)
					}
				}
				testSrv, err := NewService(testCtx, repoFn, iamRepoFn)
				require.NoError(t, err, "Error when getting new worker service.")
				return testSrv
			}(),
			scopeId: scope.Global.String(),
			req: &pbs.CreateControllerLedRequest{
				Item: &workers.Worker{
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
				Item: &workers.Worker{
					ScopeId:     scope.Global.String(),
					Name:        &wrapperspb.StringValue{Value: "success"},
					Description: &wrapperspb.StringValue{Value: "success-description"},
				},
			},
			res: &pbs.CreateControllerLedResponse{
				Item: &workers.Worker{
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
				}
			}
			assert.Equal(tc.res, got)
		})
	}
}

func TestService_AddWorkerTags(t *testing.T) {
	t.Parallel()
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
		return server.NewRepository(rw, rw, testKms)
	}
	s, err := NewService(context.Background(), repoFn, iamRepoFn)
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
	t.Parallel()
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
		return server.NewRepository(rw, rw, testKms)
	}
	s, err := NewService(context.Background(), repoFn, iamRepoFn)
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
	t.Parallel()
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
		return server.NewRepository(rw, rw, testKms)
	}
	s, err := NewService(context.Background(), repoFn, iamRepoFn)
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
