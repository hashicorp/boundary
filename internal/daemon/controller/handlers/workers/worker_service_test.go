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
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/testing/protocmp"
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
		w := servers.TestWorker(t, conn, wrap, servers.WithName(fmt.Sprintf("worker %d", i)))
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
			sort.Slice(tc.res.Items, func(i, j int) bool {
				return tc.res.Items[i].GetId() < tc.res.Items[j].GetId()
			})
			sort.Slice(got.Items, func(i, j int) bool {
				return got.Items[i].GetId() < got.Items[j].GetId()
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
