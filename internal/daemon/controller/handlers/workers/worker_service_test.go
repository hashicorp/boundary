package workers

import (
	"context"
	"fmt"
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/servers"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/scopes"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/workers"
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

var testAuthorizedActions = []string{"no-op", "read", "update", "delete"}

func TestGet(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrap)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	rw := db.New(conn)
	kms := kms.TestKms(t, conn, wrap)
	repoFn := func() (*servers.Repository, error) {
		return servers.NewRepository(rw, rw, kms)
	}

	worker := servers.TestWorker(t, conn, wrap,
		servers.WithName("test worker names"),
		servers.WithDescription("test worker description"),
		servers.WithAddress("test worker address"))

	wantWorker := &pb.Worker{
		Id:                worker.GetPublicId(),
		ScopeId:           worker.GetScopeId(),
		Scope:             &scopes.ScopeInfo{Id: worker.GetScopeId(), Type: scope.Global.String(), Name: scope.Global.String(), Description: "Global Scope"},
		CreatedTime:       worker.CreateTime.GetTimestamp(),
		UpdatedTime:       worker.UpdateTime.GetTimestamp(),
		Version:           worker.GetVersion(),
		Name:              wrapperspb.String(worker.GetName()),
		Description:       wrapperspb.String(worker.GetDescription()),
		Address:           wrapperspb.String(worker.GetAddress()),
		AuthorizedActions: testAuthorizedActions,
		CanonicalAddress:  worker.CanonicalAddress(),
		LastStatusTime:    worker.GetLastStatusTime().GetTimestamp(),
		WorkerConfig: &pb.WorkerConfig{
			Address: worker.GetWorkerReportedAddress(),
			Name:    worker.GetWorkerReportedName(),
		},
	}

	cases := []struct {
		name    string
		scopeId string
		req     *pbs.GetWorkerRequest
		res     *pbs.GetWorkerResponse
		err     error
	}{
		{
			name:    "Get an Existing Worker",
			scopeId: worker.GetScopeId(),
			req:     &pbs.GetWorkerRequest{Id: worker.GetPublicId()},
			res:     &pbs.GetWorkerResponse{Item: wantWorker},
		},
		{
			name: "Get a non existant Worker",
			req:  &pbs.GetWorkerRequest{Id: servers.WorkerPrefix + "_DoesntExis"},
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
			name: "space in id",
			req:  &pbs.GetWorkerRequest{Id: servers.WorkerPrefix + "_1 23456789"},
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
	repoFn := func() (*servers.Repository, error) {
		return servers.NewRepository(rw, rw, kms)
	}

	var wantWorkers []*pb.Worker
	for i := 0; i < 10; i++ {
		w := servers.TestWorker(t, conn, wrap, servers.WithName(fmt.Sprintf("worker%d", i)))
		wantWorkers = append(wantWorkers, &pb.Worker{
			Id:                w.GetPublicId(),
			ScopeId:           w.GetScopeId(),
			Scope:             &scopes.ScopeInfo{Id: w.GetScopeId(), Type: scope.Global.String(), Name: scope.Global.String(), Description: "Global Scope"},
			CreatedTime:       w.CreateTime.GetTimestamp(),
			UpdatedTime:       w.UpdateTime.GetTimestamp(),
			Version:           w.GetVersion(),
			Name:              wrapperspb.String(w.GetName()),
			AuthorizedActions: testAuthorizedActions,
			CanonicalAddress:  w.CanonicalAddress(),
			LastStatusTime:    w.GetLastStatusTime().GetTimestamp(),
			WorkerConfig: &pb.WorkerConfig{
				Address: w.GetWorkerReportedAddress(),
				Name:    w.GetWorkerReportedName(),
			},
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
			res:  &pbs.ListWorkersResponse{Items: wantWorkers},
		},
		{
			name: "List global workers recursively",
			req:  &pbs.ListWorkersRequest{ScopeId: "global", Recursive: true},
			res: &pbs.ListWorkersResponse{
				Items: wantWorkers,
			},
		},
		{
			name: "Filter to a single workers",
			req:  &pbs.ListWorkersRequest{ScopeId: "global", Recursive: true, Filter: `"/item/name"=="worker2"`},
			res: &pbs.ListWorkersResponse{
				Items: wantWorkers[2:3],
			},
		},
		{
			name: "Filter to 2 workers",
			req:  &pbs.ListWorkersRequest{ScopeId: "global", Recursive: true, Filter: `"/item/name" matches "worker[23]"`},
			res: &pbs.ListWorkersResponse{
				Items: wantWorkers[2:4],
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
	repoFn := func() (*servers.Repository, error) {
		return servers.NewRepository(rw, rw, kms)
	}
	ctx := context.Background()

	s, err := NewService(ctx, repoFn, iamRepoFn)
	require.NoError(t, err, "Error when getting new worker service.")

	w := servers.TestWorker(t, conn, wrap)

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
				Id: servers.WorkerPrefix + "_doesntexis",
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
	repo, err := servers.NewRepository(rw, rw, kms)
	require.NoError(t, err)
	repoFn := func() (*servers.Repository, error) {
		return repo, nil
	}

	wkr := servers.TestWorker(t, conn, wrapper,
		servers.WithName("default"),
		servers.WithDescription("default"),
		servers.WithAddress("default"))

	version := wkr.GetVersion()

	resetWorker := func() {
		version++
		_, _, err = repo.UpdateWorker(context.Background(), wkr, version, []string{"Name", "Description", "Address"})
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
	expectedConfig := &pb.WorkerConfig{
		Address: wkr.GetWorkerReportedAddress(),
		Name:    wkr.GetWorkerReportedName(),
	}

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
					Paths: []string{"name", "description", "address"},
				},
				Item: &pb.Worker{
					Name:        wrapperspb.String("name"),
					Description: wrapperspb.String("desc"),
					Address:     wrapperspb.String("address"),
				},
			},
			res: &pbs.UpdateWorkerResponse{
				Item: &pb.Worker{
					Id:                wkr.GetPublicId(),
					ScopeId:           wkr.GetScopeId(),
					Scope:             expectedScope,
					Name:              wrapperspb.String("name"),
					Description:       wrapperspb.String("desc"),
					Address:           wrapperspb.String("address"),
					CanonicalAddress:  "address",
					CreatedTime:       wkr.GetCreateTime().GetTimestamp(),
					LastStatusTime:    wkr.GetLastStatusTime().GetTimestamp(),
					WorkerConfig:      expectedConfig,
					AuthorizedActions: testAuthorizedActions,
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
					Id:                wkr.GetPublicId(),
					ScopeId:           wkr.GetScopeId(),
					Scope:             expectedScope,
					Name:              wrapperspb.String("name"),
					Description:       wrapperspb.String("desc"),
					Address:           wrapperspb.String("default"),
					CanonicalAddress:  "default",
					CreatedTime:       wkr.GetCreateTime().GetTimestamp(),
					LastStatusTime:    wkr.GetLastStatusTime().GetTimestamp(),
					WorkerConfig:      expectedConfig,
					AuthorizedActions: testAuthorizedActions,
				},
			},
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
			name: "Update port to 0",
			req: &pbs.UpdateWorkerRequest{
				UpdateMask: &field_mask.FieldMask{Paths: []string{"default_port"}},
				Item:       &pb.Worker{},
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
					Id:                wkr.GetPublicId(),
					ScopeId:           wkr.GetScopeId(),
					Scope:             expectedScope,
					Description:       wrapperspb.String("default"),
					Address:           wrapperspb.String("default"),
					CanonicalAddress:  "default",
					CreatedTime:       wkr.GetCreateTime().GetTimestamp(),
					LastStatusTime:    wkr.GetLastStatusTime().GetTimestamp(),
					WorkerConfig:      expectedConfig,
					AuthorizedActions: testAuthorizedActions,
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
					Id:                wkr.GetPublicId(),
					ScopeId:           wkr.GetScopeId(),
					Scope:             expectedScope,
					Name:              wrapperspb.String("default"),
					Address:           wrapperspb.String("default"),
					CanonicalAddress:  "default",
					CreatedTime:       wkr.GetCreateTime().GetTimestamp(),
					LastStatusTime:    wkr.GetLastStatusTime().GetTimestamp(),
					WorkerConfig:      expectedConfig,
					AuthorizedActions: testAuthorizedActions,
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
					Id:                wkr.GetPublicId(),
					ScopeId:           wkr.GetScopeId(),
					Scope:             expectedScope,
					Name:              wrapperspb.String("updated"),
					Description:       wrapperspb.String("default"),
					Address:           wrapperspb.String("default"),
					CanonicalAddress:  "default",
					CreatedTime:       wkr.GetCreateTime().GetTimestamp(),
					LastStatusTime:    wkr.GetLastStatusTime().GetTimestamp(),
					WorkerConfig:      expectedConfig,
					AuthorizedActions: testAuthorizedActions,
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
					Id:                wkr.GetPublicId(),
					ScopeId:           wkr.GetScopeId(),
					Scope:             expectedScope,
					Name:              wrapperspb.String("default"),
					Description:       wrapperspb.String("notignored"),
					Address:           wrapperspb.String("default"),
					CanonicalAddress:  "default",
					CreatedTime:       wkr.GetCreateTime().GetTimestamp(),
					LastStatusTime:    wkr.GetLastStatusTime().GetTimestamp(),
					WorkerConfig:      expectedConfig,
					AuthorizedActions: testAuthorizedActions,
				},
			},
		},
		{
			name: "Update a Non Existing Worker",
			req: &pbs.UpdateWorkerRequest{
				Id: servers.WorkerPrefix + "_DoesntExis",
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
			name: "Cant change Worker Defined Name",
			req: &pbs.UpdateWorkerRequest{
				Id: wkr.GetPublicId(),
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"worker_config.name"},
				},
				Item: &pb.Worker{
					WorkerConfig: &pb.WorkerConfig{
						Name: "name",
					},
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Cant change Worker Defined Address",
			req: &pbs.UpdateWorkerRequest{
				Id: wkr.GetPublicId(),
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"worker_config.address"},
				},
				Item: &pb.Worker{
					WorkerConfig: &pb.WorkerConfig{
						Address: "address",
					},
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
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
					Tags: map[string]*structpb.ListValue{
						"foo": func() *structpb.ListValue {
							l, err := structpb.NewList([]interface{}{"bar"})
							require.NoError(t, err)
							return l
						}(),
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
						"foo": func() *structpb.ListValue {
							l, err := structpb.NewList([]interface{}{"bar"})
							require.NoError(t, err)
							return l
						}(),
					},
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Cant specify canonical address",
			req: &pbs.UpdateWorkerRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"canonical_address"},
				},
				Item: &pb.Worker{
					CanonicalAddress: "should_fail",
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
	repo, err := servers.NewRepository(rw, rw, kms)
	require.NoError(t, err, "Couldn't create new worker repo.")
	repoFn := func() (*servers.Repository, error) {
		return repo, nil
	}
	ctx := context.Background()

	workerService, err := NewService(ctx, repoFn, iamRepoFn)
	require.NoError(t, err, "Failed to create a new host set service.")

	wkr := servers.TestWorker(t, conn, wrapper)

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
