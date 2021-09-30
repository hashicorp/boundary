package target

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/credential/vault"
	"github.com/hashicorp/boundary/internal/db"
	dbassert "github.com/hashicorp/boundary/internal/db/assert"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestRepository_CreateTcpTarget(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)
	repo, err := NewRepository(rw, rw, testKms)
	require.NoError(t, err)
	_, proj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

	cats := static.TestCatalogs(t, conn, proj.PublicId, 1)
	hsets := static.TestSets(t, conn, cats[0].GetPublicId(), 2)
	var sets []string
	for _, s := range hsets {
		sets = append(sets, s.PublicId)
	}

	cs := vault.TestCredentialStores(t, conn, wrapper, proj.GetPublicId(), 1)[0]
	credSources := vault.TestCredentialLibraries(t, conn, wrapper, cs.GetPublicId(), 2)
	var clIds []string
	for _, cl := range credSources {
		clIds = append(clIds, cl.PublicId)
	}

	type args struct {
		target *TcpTarget
		opt    []Option
	}
	tests := []struct {
		name            string
		args            args
		wantHostSources []string
		wantCredLibs    []string
		wantErr         bool
		wantIsError     errors.Code
	}{
		{
			name: "valid-org",
			args: args{
				target: func() *TcpTarget {
					target, err := NewTcpTarget(proj.PublicId,
						WithName("valid-org"),
						WithDescription("valid-org"),
						WithDefaultPort(uint32(22)))
					require.NoError(t, err)
					return target
				}(),
			},
			wantErr:         false,
			wantCredLibs:    []string{},
			wantHostSources: []string{},
		},
		{
			name: "valid-org-with-host-sets",
			args: args{
				target: func() *TcpTarget {
					target, err := NewTcpTarget(proj.PublicId,
						WithName("valid-org-with-host-sets"),
						WithDescription("valid-org"),
						WithDefaultPort(uint32(22)))
					require.NoError(t, err)
					return target
				}(),
				opt: []Option{WithHostSources(sets)},
			},
			wantErr:         false,
			wantHostSources: sets,
			wantCredLibs:    []string{},
		},
		{
			name: "valid-org-with-cred-libs",
			args: args{
				target: func() *TcpTarget {
					target, err := NewTcpTarget(proj.PublicId,
						WithName("valid-org-with-cred-libs"),
						WithDescription("valid-org"),
						WithDefaultPort(uint32(22)))
					require.NoError(t, err)
					return target
				}(),
				opt: []Option{WithCredentialSources(clIds)},
			},
			wantErr:         false,
			wantCredLibs:    clIds,
			wantHostSources: []string{},
		},
		{
			name: "valid-org-with-cred-libs-and-host-sets",
			args: args{
				target: func() *TcpTarget {
					target, err := NewTcpTarget(proj.PublicId,
						WithName("valid-org-with-cred-libs-and-host-sets"),
						WithDescription("valid-org"),
						WithDefaultPort(uint32(22)))
					require.NoError(t, err)
					return target
				}(),
				opt: []Option{
					WithHostSources(sets),
					WithCredentialSources(clIds),
				},
			},
			wantErr:         false,
			wantCredLibs:    clIds,
			wantHostSources: sets,
		},
		{
			name: "nil-target",
			args: args{
				target: nil,
			},
			wantErr:     true,
			wantIsError: errors.InvalidParameter,
		},
		{
			name: "nil-target-store",
			args: args{
				target: func() *TcpTarget {
					target := &TcpTarget{}
					return target
				}(),
			},
			wantErr:     true,
			wantIsError: errors.InvalidParameter,
		},
		{
			name: "public-id-not-empty",
			args: args{
				target: func() *TcpTarget {
					target, err := NewTcpTarget(proj.PublicId, WithName("valid-org"), WithDescription("valid-org"), WithDefaultPort(uint32(22)))
					require.NoError(t, err)
					id, err := newTcpTargetId()
					require.NoError(t, err)
					target.PublicId = id
					return target
				}(),
			},
			wantErr:     true,
			wantIsError: errors.InvalidParameter,
		},
		{
			name: "empty-scope-id",
			args: args{
				target: func() *TcpTarget {
					target := allocTcpTarget()
					target.Name = "empty-scope-id"
					require.NoError(t, err)
					return &target
				}(),
			},
			wantErr:     true,
			wantIsError: errors.InvalidParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			target, hostSources, credSources, err := repo.CreateTcpTarget(context.Background(), tt.args.target, tt.args.opt...)
			if tt.wantErr {
				assert.Error(err)
				assert.Nil(target)
				assert.True(errors.Match(errors.T(tt.wantIsError), err))
				return
			}
			require.NoError(err)
			assert.NotNil(target.GetPublicId())
			hsIds := make([]string, 0, len(hostSources))
			for _, s := range hostSources {
				hsIds = append(hsIds, s.Id())
			}
			assert.Equal(tt.wantHostSources, hsIds)

			clIds := make([]string, 0, len(credSources))
			for _, cl := range credSources {
				clIds = append(clIds, cl.Id())
			}
			assert.Equal(tt.wantCredLibs, clIds)

			foundTarget, foundHostSources, foundCredLibs, err := repo.LookupTarget(context.Background(), target.GetPublicId())
			assert.NoError(err)
			assert.True(proto.Equal(target.(*TcpTarget), foundTarget.(*TcpTarget)))
			assert.Equal(hostSources, foundHostSources)
			assert.Equal(credSources, foundCredLibs)

			err = db.TestVerifyOplog(t, rw, target.GetPublicId(), db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second))
			assert.NoError(err)

			// TODO (jimlambrt 9/2020) - unfortunately, we can currently
			// test to make sure that the oplog entry for a target host sets
			// create exist because the db.TestVerifyOplog doesn't really
			// support that level of testing and the previous call to
			// CreateTcpTarget would create an oplog entry for the
			// create on the target even if no host sets were added.   Once
			// TestVerifyOplog supports the appropriate granularity, we should
			// add an appropriate assert.
		})
	}
}

func TestRepository_UpdateTcpTarget(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)

	repo, err := NewRepository(rw, rw, testKms)
	require.NoError(t, err)
	id := testId(t)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	_, proj := iam.TestScopes(t, iamRepo)
	pubId := func(s string) *string { return &s }

	type args struct {
		name           string
		description    string
		port           uint32
		fieldMaskPaths []string
		opt            []Option
		ScopeId        string
		PublicId       *string
	}
	tests := []struct {
		name           string
		newScopeId     string
		newName        string
		newTargetOpts  []Option
		args           args
		wantRowsUpdate int
		wantErr        bool
		wantErrMsg     string
		wantIsError    errors.Code
		wantDup        bool
	}{
		{
			name: "valid",
			args: args{
				name:           "valid" + id,
				fieldMaskPaths: []string{"Name"},
				ScopeId:        proj.PublicId,
			},
			newScopeId:     proj.PublicId,
			wantErr:        false,
			wantRowsUpdate: 1,
		},
		{
			name: "valid-no-op",
			args: args{
				name:           "valid-no-op" + id,
				fieldMaskPaths: []string{"Name"},
				ScopeId:        proj.PublicId,
			},
			newScopeId:     proj.PublicId,
			newName:        "valid-no-op" + id,
			wantErr:        false,
			wantRowsUpdate: 1,
		},
		{
			name: "not-found",
			args: args{
				name:           "not-found" + id,
				fieldMaskPaths: []string{"Name"},
				ScopeId:        proj.PublicId,
				PublicId:       func() *string { s := "1"; return &s }(),
			},
			newScopeId:     proj.PublicId,
			wantErr:        true,
			wantRowsUpdate: 0,
			wantErrMsg:     "target.(Repository).UpdateTcpTarget: failed for 1: db.DoTx: target.(Repository).UpdateTcpTarget: target.(Repository).update: db.DoTx: target.(Repository).update: db.Update: db.lookupAfterWrite: db.LookupById: record not found, search issue: error #1100",
			wantIsError:    errors.RecordNotFound,
		},
		{
			name: "null-name",
			args: args{
				name:           "",
				fieldMaskPaths: []string{"Name"},
				ScopeId:        proj.PublicId,
			},
			newScopeId:     proj.PublicId,
			newName:        "null-name" + id,
			wantErr:        true,
			wantRowsUpdate: 0,
			wantErrMsg:     "db.DoTx: target.(Repository).UpdateTcpTarget: target.(Repository).update: db.DoTx: target.(Repository).update: db.Update: name must not be empty: not null constraint violated: integrity violation: error #1001",
		},
		{
			name: "null-description",
			args: args{
				name:           "null-description",
				fieldMaskPaths: []string{"Description"},
				ScopeId:        proj.PublicId,
			},
			newScopeId:     proj.PublicId,
			newTargetOpts:  []Option{WithDescription("null-description" + id)},
			wantErr:        false,
			wantRowsUpdate: 1,
		},
		{
			name: "empty-field-mask",
			args: args{
				name:           "valid" + id,
				fieldMaskPaths: []string{},
				ScopeId:        proj.PublicId,
			},
			newScopeId:     proj.PublicId,
			wantErr:        true,
			wantRowsUpdate: 0,
			wantErrMsg:     "target.(Repository).UpdateTcpTarget: empty field mask: parameter violation: error #104",
			wantIsError:    errors.EmptyFieldMask,
		},
		{
			name: "nil-fieldmask",
			args: args{
				name:           "valid" + id,
				fieldMaskPaths: nil,
				ScopeId:        proj.PublicId,
			},
			newScopeId:     proj.PublicId,
			wantErr:        true,
			wantRowsUpdate: 0,
			wantErrMsg:     "target.(Repository).UpdateTcpTarget: empty field mask: parameter violation: error #104",
			wantIsError:    errors.EmptyFieldMask,
		},
		{
			name: "read-only-fields",
			args: args{
				name:           "valid" + id,
				fieldMaskPaths: []string{"CreateTime"},
				ScopeId:        proj.PublicId,
			},
			newScopeId:     proj.PublicId,
			wantErr:        true,
			wantRowsUpdate: 0,
			wantErrMsg:     "target.(Repository).UpdateTcpTarget: invalid field mask: CreateTime: parameter violation: error #103",
			wantIsError:    errors.InvalidFieldMask,
		},
		{
			name: "unknown-fields",
			args: args{
				name:           "valid" + id,
				fieldMaskPaths: []string{"Alice"},
				ScopeId:        proj.PublicId,
			},
			newScopeId:     proj.PublicId,
			wantErr:        true,
			wantRowsUpdate: 0,
			wantErrMsg:     "target.(Repository).UpdateTcpTarget: invalid field mask: Alice: parameter violation: error #103",
			wantIsError:    errors.InvalidFieldMask,
		},
		{
			name: "no-public-id",
			args: args{
				name:           "valid" + id,
				fieldMaskPaths: []string{"Name"},
				ScopeId:        proj.PublicId,
				PublicId:       pubId(""),
			},
			newScopeId:     proj.PublicId,
			wantErr:        true,
			wantErrMsg:     "target.(Repository).UpdateTcpTarget: missing target public id: parameter violation: error #100",
			wantIsError:    errors.InvalidParameter,
			wantRowsUpdate: 0,
		},
		{
			name: "proj-scope-id-no-mask",
			args: args{
				name:    "proj-scope-id" + id,
				ScopeId: proj.PublicId,
			},
			newScopeId:  proj.PublicId,
			wantErr:     true,
			wantErrMsg:  "target.(Repository).UpdateTcpTarget: empty field mask: parameter violation: error #104",
			wantIsError: errors.EmptyFieldMask,
		},
		{
			name: "empty-scope-id-with-name-mask",
			args: args{
				name:           "empty-scope-id" + id,
				fieldMaskPaths: []string{"Name"},
				ScopeId:        "",
			},
			newScopeId:     proj.PublicId,
			wantErr:        false,
			wantRowsUpdate: 1,
		},
		{
			name: "dup-name",
			args: args{
				name:           "dup-name" + id,
				fieldMaskPaths: []string{"Name"},
				ScopeId:        proj.PublicId,
			},
			newScopeId:  proj.PublicId,
			wantErr:     true,
			wantDup:     true,
			wantErrMsg:  " already exists in scope " + proj.PublicId,
			wantIsError: errors.NotUnique,
		},
	}
	css := vault.TestCredentialStores(t, conn, wrapper, proj.GetPublicId(), len(tests))
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cs := css[i]
			require, assert := require.New(t), assert.New(t)
			if tt.wantDup {
				_ = TestTcpTarget(t, conn, proj.PublicId, tt.args.name)
			}

			testCats := static.TestCatalogs(t, conn, proj.PublicId, 1)
			hsets := static.TestSets(t, conn, testCats[0].GetPublicId(), 5)
			testHostSetIds := make([]string, 0, len(hsets))
			for _, hs := range hsets {
				testHostSetIds = append(testHostSetIds, hs.PublicId)
			}

			cls := vault.TestCredentialLibraries(t, conn, wrapper, cs.GetPublicId(), 5)
			var testClIds []string
			for _, cl := range cls {
				testClIds = append(testClIds, cl.PublicId)
			}

			tt.newTargetOpts = append(tt.newTargetOpts, WithHostSources(testHostSetIds), WithCredentialSources(testClIds))
			name := tt.newName
			if name == "" {
				name = testId(t)
			}
			target := TestTcpTarget(t, conn, tt.newScopeId, name, tt.newTargetOpts...)
			updateTarget := allocTcpTarget()
			updateTarget.PublicId = target.PublicId
			if tt.args.PublicId != nil {
				updateTarget.PublicId = *tt.args.PublicId
			}
			updateTarget.ScopeId = tt.args.ScopeId
			updateTarget.Name = tt.args.name
			updateTarget.Description = tt.args.description
			updateTarget.DefaultPort = tt.args.port

			targetAfterUpdate, hostSources, credSources, updatedRows, err := repo.UpdateTcpTarget(context.Background(), &updateTarget, target.Version, tt.args.fieldMaskPaths, tt.args.opt...)
			if tt.wantErr {
				assert.Error(err)
				assert.True(errors.Match(errors.T(tt.wantIsError), err))
				assert.Nil(targetAfterUpdate)
				assert.Equal(0, updatedRows)
				assert.Contains(err.Error(), tt.wantErrMsg)
				err = db.TestVerifyOplog(t, rw, target.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second))
				assert.Error(err)
				assert.True(errors.IsNotFoundError(err))
				return
			}
			require.NoError(err)
			require.NotNil(targetAfterUpdate)
			assert.Equal(tt.wantRowsUpdate, updatedRows)
			afterUpdateIds := make([]string, 0, len(hostSources))
			for _, hs := range hostSources {
				afterUpdateIds = append(afterUpdateIds, hs.Id())
			}
			assert.Equal(testHostSetIds, afterUpdateIds)

			afterUpdateIds = make([]string, 0, len(credSources))
			for _, cl := range credSources {
				afterUpdateIds = append(afterUpdateIds, cl.Id())
			}
			assert.Equal(testClIds, afterUpdateIds)

			switch tt.name {
			case "valid-no-op":
				assert.Equal(target.UpdateTime, targetAfterUpdate.(*TcpTarget).UpdateTime)
			default:
				assert.NotEqual(target.UpdateTime, targetAfterUpdate.(*TcpTarget).UpdateTime)
			}
			foundTarget, _, _, err := repo.LookupTarget(context.Background(), target.PublicId)
			assert.NoError(err)
			assert.True(proto.Equal(targetAfterUpdate.((*TcpTarget)), foundTarget.((*TcpTarget))))
			underlyingDB, err := conn.SqlDB(ctx)
			require.NoError(err)
			dbassert := dbassert.New(t, underlyingDB)
			if tt.args.description == "" {
				assert.Equal(foundTarget.GetDescription(), "")
				dbassert.IsNull(foundTarget, "description")
			}
			err = db.TestVerifyOplog(t, rw, target.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second))
			assert.NoError(err)
		})
	}
}
