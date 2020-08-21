package target

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestNewRepository(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)
	type args struct {
		r   db.Reader
		w   db.Writer
		kms *kms.Kms
	}
	tests := []struct {
		name          string
		args          args
		want          *Repository
		wantErr       bool
		wantErrString string
	}{
		{
			name: "valid",
			args: args{
				r:   rw,
				w:   rw,
				kms: testKms,
			},
			want: &Repository{
				reader:       rw,
				writer:       rw,
				kms:          testKms,
				defaultLimit: db.DefaultLimit,
			},
			wantErr: false,
		},
		{
			name: "nil-kms",
			args: args{
				r:   rw,
				w:   rw,
				kms: nil,
			},
			want:          nil,
			wantErr:       true,
			wantErrString: "error creating db repository with nil kms",
		},
		{
			name: "nil-writer",
			args: args{
				r:   rw,
				w:   nil,
				kms: testKms,
			},
			want:          nil,
			wantErr:       true,
			wantErrString: "error creating db repository with nil writer",
		},
		{
			name: "nil-reader",
			args: args{
				r:   nil,
				w:   rw,
				kms: testKms,
			},
			want:          nil,
			wantErr:       true,
			wantErrString: "error creating db repository with nil reader",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewRepository(tt.args.r, tt.args.w, tt.args.kms)
			if tt.wantErr {
				require.Error(err)
				assert.Equal(err.Error(), tt.wantErrString)
				return
			}
			require.NoError(err)
			assert.Equal(tt.want, got)
		})
	}
}

func TestRepository_ListTargets(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	const testLimit = 10
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	org, proj := iam.TestScopes(t, iamRepo)
	rw := db.New(conn)
	repo, err := NewRepository(rw, rw, testKms)
	require.NoError(t, err)
	repo.defaultLimit = testLimit

	type args struct {
		opt []Option
	}
	tests := []struct {
		name           string
		createCnt      int
		createScopeId  string
		createScopeId2 string
		grantUserId    string
		args           args
		wantCnt        int
		wantErr        bool
	}{
		{
			name:          "tcp-target",
			createCnt:     5,
			createScopeId: org.PublicId,
			args: args{
				opt: []Option{WithTargetType(TcpTargetType), WithScopeId(org.PublicId)},
			},
			wantCnt: 5,
			wantErr: false,
		},
		{
			name:          "no-limit-org",
			createCnt:     testLimit + 1,
			createScopeId: org.PublicId,
			args: args{
				opt: []Option{WithLimit(-1), WithScopeId(org.PublicId)},
			},
			wantCnt: testLimit + 1,
			wantErr: false,
		},
		{
			name:          "no-limit-proj",
			createCnt:     testLimit + 1,
			createScopeId: proj.PublicId,
			args: args{
				opt: []Option{WithLimit(-1), WithScopeId(proj.PublicId)},
			},
			wantCnt: testLimit + 1,
			wantErr: false,
		},
		{
			name:          "default-limit",
			createCnt:     testLimit + 1,
			createScopeId: org.PublicId,
			args: args{
				opt: []Option{WithScopeId(org.PublicId)},
			},
			wantCnt: testLimit,
			wantErr: false,
		},
		{
			name:          "custom-limit",
			createCnt:     testLimit + 1,
			createScopeId: org.PublicId,
			args: args{
				opt: []Option{WithLimit(3), WithScopeId(org.PublicId)},
			},
			wantCnt: 3,
			wantErr: false,
		},
		{
			name:          "bad-org",
			createCnt:     1,
			createScopeId: org.PublicId,
			args: args{
				opt: []Option{WithScopeId("bad-id")},
			},
			wantCnt: 0,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			require.NoError(conn.Where("1=1").Delete(allocTcpTarget()).Error)
			testGroups := []*TcpTarget{}
			for i := 0; i < tt.createCnt; i++ {
				switch {
				case tt.createScopeId2 != "" && i%2 == 0:
					testGroups = append(testGroups, TestTcpTarget(t, conn, tt.createScopeId2, strconv.Itoa(i)))
				default:
					testGroups = append(testGroups, TestTcpTarget(t, conn, tt.createScopeId, strconv.Itoa(i)))
				}
			}
			assert.Equal(tt.createCnt, len(testGroups))
			conn.LogMode(true)
			got, err := repo.ListTargets(context.Background(), tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				return
			}
			require.NoError(err)
			assert.Equal(tt.wantCnt, len(got))
		})
	}
}

func TestRepository_DeleteTarget(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	org, _ := iam.TestScopes(t, iamRepo)
	repo, err := NewRepository(rw, rw, testKms)
	require.NoError(t, err)

	type args struct {
		target Target
		opt    []Option
	}
	tests := []struct {
		name            string
		args            args
		wantRowsDeleted int
		wantErr         bool
		wantErrMsg      string
	}{
		{
			name: "valid",
			args: args{
				target: TestTcpTarget(t, conn, org.PublicId, "valid"),
			},
			wantRowsDeleted: 1,
			wantErr:         false,
		},
		{
			name: "no-public-id",
			args: args{
				target: func() Target {
					target := allocTcpTarget()
					return &target
				}(),
			},
			wantRowsDeleted: 0,
			wantErr:         true,
			wantErrMsg:      "delete target: missing public id nil parameter",
		},
		{
			name: "not-found",
			args: args{
				target: func() Target {
					id, err := newTcpTargetId()
					require.NoError(t, err)
					target := allocTcpTarget()
					target.PublicId = id
					return target
				}(),
			},
			wantRowsDeleted: 0,
			wantErr:         true,
			wantErrMsg:      "delete target: failed record not found for ",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			deletedRows, err := repo.DeleteTarget(context.Background(), tt.args.target.GetPublicId(), tt.args.opt...)
			if tt.wantErr {
				assert.Error(err)
				assert.Equal(0, deletedRows)
				assert.Contains(err.Error(), tt.wantErrMsg)
				err = db.TestVerifyOplog(t, rw, tt.args.target.GetPublicId(), db.WithOperation(oplog.OpType_OP_TYPE_DELETE), db.WithCreateNotBefore(10*time.Second))
				assert.Error(err)
				assert.True(errors.Is(db.ErrRecordNotFound, err))
				return
			}
			assert.NoError(err)
			assert.Equal(tt.wantRowsDeleted, deletedRows)
			foundGroup, _, err := repo.LookupTarget(context.Background(), tt.args.target.GetPublicId())
			assert.Error(err)
			assert.Nil(foundGroup)
			assert.True(errors.Is(err, db.ErrRecordNotFound))

			err = db.TestVerifyOplog(t, rw, tt.args.target.GetPublicId(), db.WithOperation(oplog.OpType_OP_TYPE_DELETE), db.WithCreateNotBefore(10*time.Second))
			assert.NoError(err)
		})
	}
}

func TestRepository_AddTargetHostSets(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	staticOrg, staticProj := iam.TestScopes(t, iamRepo)
	orgTarget := TestTcpTarget(t, conn, staticOrg.PublicId, "static-org")
	projTarget := TestTcpTarget(t, conn, staticProj.PublicId, "static-proj")
	repo, err := NewRepository(rw, rw, testKms)
	require.NoError(t, err)

	_, _, err = repo.LookupTarget(context.Background(), orgTarget.PublicId)
	require.NoError(t, err)
	_, _, err = repo.LookupTarget(context.Background(), projTarget.PublicId)
	require.NoError(t, err)

	createHostSetsFn := func(orgs, projects []string) []string {
		results := []string{}
		for _, publicId := range orgs {
			cats := static.TestCatalogs(t, conn, publicId, 1)
			hsets := static.TestSets(t, conn, cats[0].GetPublicId(), 1)
			results = append(results, hsets[0].PublicId)
		}
		for _, publicId := range projects {
			cats := static.TestCatalogs(t, conn, publicId, 1)
			hsets := static.TestSets(t, conn, cats[0].GetPublicId(), 1)
			results = append(results, hsets[0].PublicId)
		}
		return results
	}

	type args struct {
		targetVersion uint32
		wantTargetIds bool
		opt           []Option
	}
	tests := []struct {
		name      string
		args      args
		wantErr   bool
		wantErrIs error
	}{
		{
			name: "valid",
			args: args{
				targetVersion: 1,
				wantTargetIds: true,
			},
			wantErr: false,
		},
		{
			name: "bad-version",
			args: args{
				targetVersion: 1000,
				wantTargetIds: true,
			},
			wantErr: true,
		},
		{
			name: "zero-version",
			args: args{
				targetVersion: 0,
				wantTargetIds: true,
			},
			wantErr: true,
		},
		{
			name: "no-host-sets",
			args: args{
				targetVersion: 1,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			require.NoError(conn.Where("1=1").Delete(allocTargetHostSet()).Error)
			var hostSetIds []string
			for _, targetId := range []string{projTarget.PublicId, orgTarget.PublicId} {
				origTarget, origHostSet, err := repo.LookupTarget(context.Background(), targetId)
				require.NoError(err)
				require.Equal(0, len(origHostSet))

				if tt.args.wantTargetIds {
					hostSetIds = createHostSetsFn([]string{staticOrg.PublicId}, []string{staticProj.PublicId})
				}

				gotTarget, gotHostSets, err := repo.AddTargeHostSets(context.Background(), targetId, tt.args.targetVersion, hostSetIds, tt.args.opt...)
				if tt.wantErr {
					require.Error(err)
					if tt.wantErrIs != nil {
						assert.Truef(errors.Is(err, tt.wantErrIs), "unexpected error %s", err.Error())
					}
					return
				}
				require.NoError(err)
				gotHostSet := map[string]bool{}
				for _, id := range gotHostSets {
					gotHostSet[id] = true
				}
				err = db.TestVerifyOplog(t, rw, targetId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second))
				assert.NoError(err)

				foundHostSets, err := fetchHostSets(context.Background(), rw, targetId)
				require.NoError(err)
				for _, id := range foundHostSets {
					assert.NotEmpty(gotHostSet[id])
				}

				t, ths, err := repo.LookupTarget(context.Background(), targetId)
				require.NoError(err)
				assert.Equal(tt.args.targetVersion+1, t.GetVersion())
				assert.Equal(origTarget.GetVersion(), t.GetVersion()-1)
				assert.Equal(gotHostSets, ths)
				assert.True(proto.Equal(gotTarget.(*TcpTarget), t.(*TcpTarget)))
			}
		})
	}
}

func TestRepository_DeleteTargetHosts(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	org, _ := iam.TestScopes(t, iamRepo)
	repo, err := NewRepository(rw, rw, testKms)
	require.NoError(t, err)

	type args struct {
		target                Target
		targetIdOverride      *string
		targetVersionOverride *uint32
		createCnt             int
		deleteCnt             int
		opt                   []Option
	}
	tests := []struct {
		name            string
		args            args
		wantRowsDeleted int
		wantErr         bool
		wantIsErr       error
	}{
		{
			name: "valid",
			args: args{
				target:    TestTcpTarget(t, conn, org.PublicId, "valid"),
				createCnt: 5,
				deleteCnt: 5,
			},
			wantRowsDeleted: 5,
			wantErr:         false,
		},
		{
			name: "valid-keeping-some",
			args: args{
				target:    TestTcpTarget(t, conn, org.PublicId, "valid-keeping-some"),
				createCnt: 5,
				deleteCnt: 2,
			},
			wantRowsDeleted: 2,
			wantErr:         false,
		},
		{
			name: "no-deletes",
			args: args{
				target:    TestTcpTarget(t, conn, org.PublicId, "no-deletes"),
				createCnt: 5,
			},
			wantRowsDeleted: 0,
			wantErr:         true,
			wantIsErr:       db.ErrInvalidParameter,
		},
		{
			name: "not-found",
			args: args{
				target:           TestTcpTarget(t, conn, org.PublicId, "not-found"),
				targetIdOverride: func() *string { id := testId(t); return &id }(),
				createCnt:        5,
				deleteCnt:        5,
			},
			wantRowsDeleted: 0,
			wantErr:         true,
		},
		{
			name: "missing-target-id",
			args: args{
				target:           TestTcpTarget(t, conn, org.PublicId, "missing-target-id"),
				targetIdOverride: func() *string { id := ""; return &id }(),
				createCnt:        5,
				deleteCnt:        5,
			},
			wantRowsDeleted: 0,
			wantErr:         true,
			wantIsErr:       db.ErrInvalidParameter,
		},
		{
			name: "zero-version",
			args: args{
				target:                TestTcpTarget(t, conn, org.PublicId, "zero-version"),
				targetVersionOverride: func() *uint32 { v := uint32(0); return &v }(),
				createCnt:             5,
				deleteCnt:             5,
			},
			wantRowsDeleted: 0,
			wantErr:         true,
			wantIsErr:       db.ErrInvalidParameter,
		},
		{
			name: "bad-version",
			args: args{
				target:                TestTcpTarget(t, conn, org.PublicId, "bad-version"),
				targetVersionOverride: func() *uint32 { v := uint32(1000); return &v }(),
				createCnt:             5,
				deleteCnt:             5,
			},
			wantRowsDeleted: 0,
			wantErr:         true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			hsIds := make([]string, 0, tt.args.createCnt)
			if tt.args.createCnt > 0 {
				for i := 0; i < tt.args.createCnt; i++ {
					cats := static.TestCatalogs(t, conn, org.PublicId, 1)
					hsets := static.TestSets(t, conn, cats[0].GetPublicId(), 1)
					hsIds = append(hsIds, hsets[0].PublicId)
				}
			}
			_, addedHostSets, err := repo.AddTargeHostSets(context.Background(), tt.args.target.GetPublicId(), 1, hsIds, tt.args.opt...)
			require.NoError(err)
			assert.Equal(tt.args.createCnt, len(addedHostSets))

			deleteHostSets := make([]string, 0, tt.args.deleteCnt)
			for i := 0; i < tt.args.deleteCnt; i++ {
				deleteHostSets = append(deleteHostSets, hsIds[i])
			}
			var targetId string
			switch {
			case tt.args.targetIdOverride != nil:
				targetId = *tt.args.targetIdOverride
			default:
				targetId = tt.args.target.GetPublicId()
			}
			var targetVersion uint32
			switch {
			case tt.args.targetVersionOverride != nil:
				targetVersion = *tt.args.targetVersionOverride
			default:
				targetVersion = 2
			}
			deletedRows, err := repo.DeleteTargeHostSets(context.Background(), targetId, targetVersion, deleteHostSets, tt.args.opt...)
			if tt.wantErr {
				assert.Error(err)
				assert.Equal(0, deletedRows)
				if tt.wantIsErr != nil {
					assert.Truef(errors.Is(err, tt.wantIsErr), "unexpected error %s", err.Error())
				}
				err = db.TestVerifyOplog(t, rw, tt.args.target.GetPublicId(), db.WithOperation(oplog.OpType_OP_TYPE_DELETE), db.WithCreateNotBefore(10*time.Second))
				assert.Error(err)
				assert.True(errors.Is(db.ErrRecordNotFound, err))
				return
			}
			require.NoError(err)
			assert.Equal(tt.wantRowsDeleted, deletedRows)

			err = db.TestVerifyOplog(t, rw, tt.args.target.GetPublicId(), db.WithOperation(oplog.OpType_OP_TYPE_DELETE), db.WithCreateNotBefore(10*time.Second))
			assert.NoError(err)
		})
	}
}
