package target

import (
	"context"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
			wantErrString: "target.NewRepository: nil kms: parameter violation: error #100",
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
			wantErrString: "target.NewRepository: nil writer: parameter violation: error #100",
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
			wantErrString: "target.NewRepository: nil reader: parameter violation: error #100",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewRepository(tt.args.r, tt.args.w, tt.args.kms)
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

func TestRepository_LookupTarget(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	_, proj := iam.TestScopes(t, iamRepo)
	proj.Name = "project-name"
	_, _, err := iamRepo.UpdateScope(context.Background(), proj, 1, []string{"name"})
	require.NoError(t, err)
	rw := db.New(conn)
	repo, err := NewRepository(rw, rw, testKms)
	require.NoError(t, err)
	tgt := TestTcpTarget(t, conn, proj.PublicId, "target-name")

	tests := []struct {
		testName  string
		id        string
		name      string
		scopeId   string
		scopeName string
		wantErr   bool
	}{
		{
			testName: "id",
			id:       tgt.PublicId,
			wantErr:  false,
		},
		{
			testName: "name only",
			name:     tgt.Name,
			wantErr:  true,
		},
		{
			testName: "scope id only",
			scopeId:  proj.PublicId,
			wantErr:  true,
		},
		{
			testName:  "scope name only",
			scopeName: proj.Name,
			wantErr:   true,
		},
		{
			testName:  "scope name and id",
			scopeId:   proj.PublicId,
			scopeName: proj.Name,
			wantErr:   true,
		},
		{
			testName:  "everything",
			name:      tgt.Name,
			scopeId:   proj.PublicId,
			scopeName: proj.Name,
			wantErr:   true,
		},
		{
			testName:  "name and scope name",
			name:      tgt.Name,
			scopeName: proj.Name,
			wantErr:   false,
		},
		{
			testName: "name and scope id",
			name:     tgt.Name,
			scopeId:  proj.PublicId,
			wantErr:  false,
		},
		{
			testName: "id and name",
			id:       tgt.PublicId,
			name:     tgt.Name,
			scopeId:  proj.PublicId,
			wantErr:  true,
		},
		{
			testName:  "id and scope name",
			id:        tgt.PublicId,
			scopeName: proj.Name,
			wantErr:   true,
		},
		{
			testName: "id and scope id",
			id:       tgt.PublicId,
			scopeId:  proj.PublicId,
			wantErr:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.testName, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			id := tt.id
			if tt.name != "" && tt.id == "" {
				id = tt.name
			}
			var opts []Option
			if tt.name != "" {
				opts = append(opts, WithName(tt.name))
			}
			if tt.scopeId != "" {
				opts = append(opts, WithScopeId(tt.scopeId))
			}
			if tt.scopeName != "" {
				opts = append(opts, WithScopeName(tt.scopeName))
			}
			got, _, _, err := repo.LookupTarget(context.Background(), id, opts...)
			if tt.wantErr {
				require.Error(err)
				return
			}
			require.NoError(err)
			assert.Equal(tgt.PublicId, got.GetPublicId())
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
	_, proj := iam.TestScopes(t, iamRepo)
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
			createScopeId: proj.PublicId,
			args: args{
				opt: []Option{WithTargetType(TcpTargetType), WithScopeIds([]string{proj.PublicId})},
			},
			wantCnt: 5,
			wantErr: false,
		},
		{
			name:          "no-limit",
			createCnt:     testLimit + 1,
			createScopeId: proj.PublicId,
			args: args{
				opt: []Option{WithLimit(-1), WithScopeIds([]string{proj.PublicId})},
			},
			wantCnt: testLimit + 1,
			wantErr: false,
		},
		{
			name:          "default-limit",
			createCnt:     testLimit + 1,
			createScopeId: proj.PublicId,
			args: args{
				opt: []Option{WithScopeIds([]string{proj.PublicId})},
			},
			wantCnt: testLimit,
			wantErr: false,
		},
		{
			name:          "custom-limit",
			createCnt:     testLimit + 1,
			createScopeId: proj.PublicId,
			args: args{
				opt: []Option{WithLimit(3), WithScopeIds([]string{proj.PublicId})},
			},
			wantCnt: 3,
			wantErr: false,
		},
		{
			name:          "bad-org",
			createCnt:     1,
			createScopeId: proj.PublicId,
			args: args{
				opt: []Option{WithScopeIds([]string{"bad-id"})},
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

func TestRepository_ListRoles_Multiple_Scopes(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	_, proj1 := iam.TestScopes(t, iamRepo)
	_, proj2 := iam.TestScopes(t, iamRepo)
	rw := db.New(conn)
	repo, err := NewRepository(rw, rw, testKms)
	require.NoError(t, err)

	require.NoError(t, conn.Where("1=1").Delete(allocTcpTarget()).Error)

	const numPerScope = 10
	var total int
	for i := 0; i < numPerScope; i++ {
		TestTcpTarget(t, conn, proj1.GetPublicId(), fmt.Sprintf("proj1-%d", i))
		total++
		TestTcpTarget(t, conn, proj2.GetPublicId(), fmt.Sprintf("proj2-%d", i))
		total++
	}

	got, err := repo.ListTargets(context.Background(), WithScopeIds([]string{"global", proj1.GetPublicId(), proj2.GetPublicId()}))
	require.NoError(t, err)
	assert.Equal(t, total, len(got))
}

func TestRepository_DeleteTarget(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	_, proj := iam.TestScopes(t, iamRepo)
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
				target: TestTcpTarget(t, conn, proj.PublicId, "valid"),
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
			wantErrMsg:      "target.(Repository).DeleteTarget: missing public id: parameter violation: error #100",
		},
		{
			name: "not-found",
			args: args{
				target: func() Target {
					id, err := newTcpTargetId()
					require.NoError(t, err)
					target := allocTcpTarget()
					target.PublicId = id
					return &target
				}(),
			},
			wantRowsDeleted: 0,
			wantErr:         true,
			wantErrMsg:      "db.LookupById: record not found, search issue: error #1100",
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
				assert.True(errors.IsNotFoundError(err))
				return
			}
			assert.NoError(err)
			assert.Equal(tt.wantRowsDeleted, deletedRows)
			foundGroup, _, _, err := repo.LookupTarget(context.Background(), tt.args.target.GetPublicId())
			assert.NoError(err)
			assert.Nil(foundGroup)

			err = db.TestVerifyOplog(t, rw, tt.args.target.GetPublicId(), db.WithOperation(oplog.OpType_OP_TYPE_DELETE), db.WithCreateNotBefore(10*time.Second))
			assert.NoError(err)
		})
	}
}
