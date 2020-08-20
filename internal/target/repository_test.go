package target

import (
	"context"
	"strconv"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
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
