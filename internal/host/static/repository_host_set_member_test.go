package static

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestRepository_ListSetMembers(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)

	_, prj := iam.TestScopes(t, iamRepo)
	c := TestCatalogs(t, conn, prj.PublicId, 1)[0]
	sets := TestSets(t, conn, c.PublicId, 2)
	setA, setB := sets[0], sets[1]

	hosts := TestHosts(t, conn, c.PublicId, 5)
	TestSetMembers(t, conn, setA.PublicId, hosts)

	var tests = []struct {
		name      string
		in        string
		opts      []Option
		want      []*Host
		wantIsErr error
	}{
		{
			name:      "with-no-set-id",
			wantIsErr: db.ErrInvalidParameter,
		},
		{
			name: "set-with-no-hosts",
			in:   setB.PublicId,
		},
		{
			name: "set-with-hosts",
			in:   setA.PublicId,
			want: hosts,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(rw, rw, kms)
			assert.NoError(err)
			require.NotNil(repo)
			got, err := repo.ListSetMembers(context.Background(), tt.in, tt.opts...)
			if tt.wantIsErr != nil {
				assert.Truef(errors.Is(err, tt.wantIsErr), "want err: %q got: %q", tt.wantIsErr, err)
				assert.Nil(got)
				return
			}
			require.NoError(err)
			opts := []cmp.Option{
				cmpopts.SortSlices(func(x, y *Host) bool { return x.PublicId < y.PublicId }),
				protocmp.Transform(),
			}
			assert.Empty(cmp.Diff(tt.want, got, opts...))
		})
	}
}

func TestRepository_ListSetMembers_Limits(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)

	_, prj := iam.TestScopes(t, iamRepo)
	c := TestCatalogs(t, conn, prj.PublicId, 1)[0]
	set := TestSets(t, conn, c.PublicId, 1)[0]
	count := 10
	hosts := TestHosts(t, conn, c.PublicId, count)
	TestSetMembers(t, conn, set.PublicId, hosts)

	var tests = []struct {
		name     string
		repoOpts []Option
		listOpts []Option
		wantLen  int
	}{
		{
			name:    "With no limits",
			wantLen: count,
		},
		{
			name:     "With repo limit",
			repoOpts: []Option{WithLimit(3)},
			wantLen:  3,
		},
		{
			name:     "With negative repo limit",
			repoOpts: []Option{WithLimit(-1)},
			wantLen:  count,
		},
		{
			name:     "With List limit",
			listOpts: []Option{WithLimit(3)},
			wantLen:  3,
		},
		{
			name:     "With negative List limit",
			listOpts: []Option{WithLimit(-1)},
			wantLen:  count,
		},
		{
			name:     "With repo smaller than list limit",
			repoOpts: []Option{WithLimit(2)},
			listOpts: []Option{WithLimit(6)},
			wantLen:  6,
		},
		{
			name:     "With repo larger than list limit",
			repoOpts: []Option{WithLimit(6)},
			listOpts: []Option{WithLimit(2)},
			wantLen:  2,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(rw, rw, kms, tt.repoOpts...)
			assert.NoError(err)
			require.NotNil(repo)
			got, err := repo.ListSetMembers(context.Background(), set.PublicId, tt.listOpts...)
			require.NoError(err)
			assert.Len(got, tt.wantLen)
		})
	}
}

func TestRepository_AddSetMembers_InvalidParameters(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)

	_, prj := iam.TestScopes(t, iamRepo)
	c := TestCatalogs(t, conn, prj.PublicId, 1)[0]
	set := TestSets(t, conn, c.PublicId, 1)[0]
	hosts := TestHosts(t, conn, c.PublicId, 5)
	var hostIds []string
	for _, h := range hosts {
		hostIds = append(hostIds, h.PublicId)
	}

	badVersion := uint32(12345)

	type args struct {
		scopeId string
		setId   string
		version uint32
		hostIds []string
		opt     []Option
	}

	tests := []struct {
		name      string
		args      args
		want      []*Host
		wantErr   bool
		wantIsErr error
	}{
		{
			name: "empty-scope-id",
			args: args{
				setId:   set.PublicId,
				version: set.Version,
				hostIds: hostIds,
			},
			wantIsErr: db.ErrInvalidParameter,
		},
		{
			name: "empty-set-id",
			args: args{
				scopeId: prj.PublicId,
				version: set.Version,
				hostIds: hostIds,
			},
			wantIsErr: db.ErrInvalidParameter,
		},
		{
			name: "zero-version",
			args: args{
				scopeId: prj.PublicId,
				setId:   set.PublicId,
				hostIds: hostIds,
			},
			wantIsErr: db.ErrInvalidParameter,
		},
		{
			name: "empty-host-ids",
			args: args{
				scopeId: prj.PublicId,
				setId:   set.PublicId,
				version: set.Version,
			},
			wantIsErr: db.ErrInvalidParameter,
		},
		{
			name: "invalid-version",
			args: args{
				scopeId: prj.PublicId,
				setId:   set.PublicId,
				version: badVersion,
				hostIds: hostIds,
			},
			wantErr: true,
		},
		{
			name: "valid",
			args: args{
				scopeId: prj.PublicId,
				setId:   set.PublicId,
				version: set.Version,
				hostIds: hostIds,
			},
			want: hosts,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(rw, rw, kms)
			require.NoError(err)
			require.NotNil(repo)
			got, err := repo.AddSetMembers(context.Background(), tt.args.scopeId, tt.args.setId, tt.args.version, tt.args.hostIds, tt.args.opt...)
			if tt.wantIsErr != nil {
				assert.Truef(errors.Is(err, tt.wantIsErr), "want err: %q got: %q", tt.wantIsErr, err)
				assert.Nil(got)
				assert.Error(db.TestVerifyOplog(t, rw, tt.args.setId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second)))
				return
			}
			if tt.wantErr {
				assert.Error(err)
				assert.Nil(got)
				assert.Error(db.TestVerifyOplog(t, rw, tt.args.setId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second)))
				return
			}
			require.NoError(err)
			opts := []cmp.Option{
				cmpopts.SortSlices(func(x, y *Host) bool { return x.PublicId < y.PublicId }),
				protocmp.Transform(),
			}
			assert.Empty(cmp.Diff(tt.want, got, opts...))
			assert.NoError(db.TestVerifyOplog(t, rw, tt.args.setId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second)))
		})
	}
}

func TestRepository_AddSetMembers_InvalidHostCombinations(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)

	_, prj := iam.TestScopes(t, iamRepo)

	assert, require := assert.New(t), require.New(t)
	c := TestCatalogs(t, conn, prj.PublicId, 1)[0]
	set := TestSets(t, conn, c.PublicId, 1)[0]

	repo, err := NewRepository(rw, rw, kms)
	require.NoError(err)
	require.NotNil(repo)

	hosts := TestHosts(t, conn, c.PublicId, 5)
	var hostIds []string
	for _, h := range hosts {
		hostIds = append(hostIds, h.PublicId)
	}

	// first call - add first set of hosts - should succeed
	got, err := repo.AddSetMembers(context.Background(), prj.PublicId, set.PublicId, set.Version, hostIds)
	require.NoError(err)
	require.NotNil(got)

	opts := []cmp.Option{
		cmpopts.SortSlices(func(x, y *Host) bool { return x.PublicId < y.PublicId }),
		protocmp.Transform(),
	}
	assert.Empty(cmp.Diff(hosts, got, opts...))
	assert.NoError(db.TestVerifyOplog(t, rw, set.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second)))

	// second call - add new set of hosts - should succeed
	set.Version = set.Version + 1
	hosts2 := TestHosts(t, conn, c.PublicId, 5)
	var hostIds2 []string
	for _, h := range hosts2 {
		hostIds2 = append(hostIds2, h.PublicId)
	}
	got2, err2 := repo.AddSetMembers(context.Background(), prj.PublicId, set.PublicId, set.Version, hostIds2)
	require.NoError(err2)
	require.NotNil(got2)

	hosts = append(hosts, hosts2...)
	assert.Empty(cmp.Diff(hosts, got2, opts...))
	assert.NoError(db.TestVerifyOplog(t, rw, set.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second)))

	// third call - add new hosts plus a few existing hosts - should fail
	set.Version = set.Version + 1
	hosts3 := TestHosts(t, conn, c.PublicId, 5)
	var hostIds3 []string
	for _, h := range hosts3 {
		hostIds3 = append(hostIds2, h.PublicId)
	}
	hostIds3 = append(hostIds3, hostIds2...)
	got3, err3 := repo.AddSetMembers(context.Background(), prj.PublicId, set.PublicId, set.Version, hostIds3)
	require.Error(err3)
	require.Nil(got3)
}

func TestRepository_DeleteSetMembers_InvalidParameters(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)

	_, prj := iam.TestScopes(t, iamRepo)
	c := TestCatalogs(t, conn, prj.PublicId, 1)[0]
	set := TestSets(t, conn, c.PublicId, 1)[0]
	count := 5
	hosts := TestHosts(t, conn, c.PublicId, count)
	TestSetMembers(t, conn, set.PublicId, hosts)

	var hostIds []string
	for _, h := range hosts {
		hostIds = append(hostIds, h.PublicId)
	}

	badVersion := uint32(12345)

	type args struct {
		scopeId string
		setId   string
		version uint32
		hostIds []string
		opt     []Option
	}

	tests := []struct {
		name      string
		args      args
		want      int
		wantErr   bool
		wantIsErr error
	}{
		{
			name: "empty-scope-id",
			args: args{
				setId:   set.PublicId,
				version: set.Version,
				hostIds: hostIds,
			},
			wantIsErr: db.ErrInvalidParameter,
		},
		{
			name: "empty-set-id",
			args: args{
				scopeId: prj.PublicId,
				version: set.Version,
				hostIds: hostIds,
			},
			wantIsErr: db.ErrInvalidParameter,
		},
		{
			name: "zero-version",
			args: args{
				scopeId: prj.PublicId,
				setId:   set.PublicId,
				hostIds: hostIds,
			},
			wantIsErr: db.ErrInvalidParameter,
		},
		{
			name: "empty-host-ids",
			args: args{
				scopeId: prj.PublicId,
				setId:   set.PublicId,
				version: set.Version,
			},
			wantIsErr: db.ErrInvalidParameter,
		},
		{
			name: "invalid-version",
			args: args{
				scopeId: prj.PublicId,
				setId:   set.PublicId,
				version: badVersion,
				hostIds: hostIds,
			},
			wantErr: true,
		},
		{
			name: "valid",
			args: args{
				scopeId: prj.PublicId,
				setId:   set.PublicId,
				version: set.Version,
				hostIds: hostIds,
			},
			want:    count,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(rw, rw, kms)
			require.NoError(err)
			require.NotNil(repo)
			got, err := repo.DeleteSetMembers(context.Background(), tt.args.scopeId, tt.args.setId, tt.args.version, tt.args.hostIds, tt.args.opt...)
			if tt.wantIsErr != nil {
				assert.Truef(errors.Is(err, tt.wantIsErr), "want err: %q got: %q", tt.wantIsErr, err)
				assert.Zero(got)
				assert.Error(db.TestVerifyOplog(t, rw, tt.args.setId, db.WithOperation(oplog.OpType_OP_TYPE_DELETE), db.WithCreateNotBefore(10*time.Second)))
				return
			}
			if tt.wantErr {
				assert.Error(err)
				assert.Zero(got)
				assert.Error(db.TestVerifyOplog(t, rw, tt.args.setId, db.WithOperation(oplog.OpType_OP_TYPE_DELETE), db.WithCreateNotBefore(10*time.Second)))
				return
			}
			assert.NoError(err)
			assert.Equal(tt.want, got)
			assert.NoError(db.TestVerifyOplog(t, rw, tt.args.setId, db.WithOperation(oplog.OpType_OP_TYPE_DELETE), db.WithCreateNotBefore(10*time.Second)))
		})
	}
}

func TestRepository_DeleteSetMembers_InvalidHostCombinations(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)

	_, prj := iam.TestScopes(t, iamRepo)

	assert, require := assert.New(t), require.New(t)
	c := TestCatalogs(t, conn, prj.PublicId, 1)[0]
	set := TestSets(t, conn, c.PublicId, 1)[0]

	repo, err := NewRepository(rw, rw, kms)
	require.NoError(err)
	require.NotNil(repo)

	count := 10
	hosts := TestHosts(t, conn, c.PublicId, count)
	TestSetMembers(t, conn, set.PublicId, hosts)

	var hostIds []string
	for _, h := range hosts {
		hostIds = append(hostIds, h.PublicId)
	}
	split := 5
	idsA := hostIds[:split]
	hostsB, idsB := hosts[split:], hostIds[split:]

	// first call - delete first half of hosts - should succeed
	got, err := repo.DeleteSetMembers(context.Background(), prj.PublicId, set.PublicId, set.Version, idsA)
	assert.NoError(err)
	require.Equal(len(idsA), got)
	assert.NoError(db.TestVerifyOplog(t, rw, set.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_DELETE), db.WithCreateNotBefore(10*time.Second)))

	// verify hostsB are still members
	members, err := repo.ListSetMembers(context.Background(), set.PublicId)
	require.NoError(err)

	opts := []cmp.Option{
		cmpopts.SortSlices(func(x, y *Host) bool { return x.PublicId < y.PublicId }),
		protocmp.Transform(),
	}
	assert.Empty(cmp.Diff(hostsB, members, opts...))

	// second call - delete first half of hosts again - should fail
	set.Version = set.Version + 1
	got2, err2 := repo.DeleteSetMembers(context.Background(), prj.PublicId, set.PublicId, set.Version, idsA)
	require.Error(err2)
	assert.Zero(got2)

	// third call - delete first half and second half - should fail
	got3, err3 := repo.DeleteSetMembers(context.Background(), prj.PublicId, set.PublicId, set.Version, hostIds)
	require.Error(err3)
	assert.Zero(got3)

	// fourth call - delete second half of hosts - should succeed
	got4, err4 := repo.DeleteSetMembers(context.Background(), prj.PublicId, set.PublicId, set.Version, idsB)
	assert.NoError(err4)
	require.Equal(len(idsB), got4)
	assert.NoError(db.TestVerifyOplog(t, rw, set.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_DELETE), db.WithCreateNotBefore(10*time.Second)))

	// verify no members remain
	members2, err := repo.ListSetMembers(context.Background(), set.PublicId)
	require.NoError(err)
	require.Empty(members2)
}
