// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package static

import (
	"context"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestRepository_AddSetMembers_Parameters(t *testing.T) {
	ctx := context.Background()
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
		projectId string
		setId     string
		version   uint32
		hostIds   []string
		opt       []Option
	}

	tests := []struct {
		name      string
		args      args
		want      []*Host
		wantErr   bool
		wantIsErr errors.Code
	}{
		{
			name: "empty-project-id",
			args: args{
				setId:   set.PublicId,
				version: set.Version,
				hostIds: hostIds,
			},
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "empty-set-id",
			args: args{
				projectId: prj.PublicId,
				version:   set.Version,
				hostIds:   hostIds,
			},
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "zero-version",
			args: args{
				projectId: prj.PublicId,
				setId:     set.PublicId,
				hostIds:   hostIds,
			},
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "empty-host-ids",
			args: args{
				projectId: prj.PublicId,
				setId:     set.PublicId,
				version:   set.Version,
			},
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "invalid-version",
			args: args{
				projectId: prj.PublicId,
				setId:     set.PublicId,
				version:   badVersion,
				hostIds:   hostIds,
			},
			wantErr: true,
		},
		{
			name: "valid",
			args: args{
				projectId: prj.PublicId,
				setId:     set.PublicId,
				version:   set.Version,
				hostIds:   hostIds,
			},
			want: hosts,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(ctx, rw, rw, kms)
			require.NoError(err)
			require.NotNil(repo)
			got, err := repo.AddSetMembers(ctx, tt.args.projectId, tt.args.setId, tt.args.version, tt.args.hostIds, tt.args.opt...)
			if tt.wantIsErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantIsErr), err), "want err: %q got: %q", tt.wantIsErr, err)
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
			assert.Len(got, len(tt.want))
			assert.Empty(cmp.Diff(tt.want, got, opts...))
			assert.NoError(db.TestVerifyOplog(t, rw, tt.args.setId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second)))
		})
	}
}

func TestRepository_AddSetMembers_Combinations(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)

	_, prj := iam.TestScopes(t, iamRepo)

	assert, require := assert.New(t), require.New(t)
	c := TestCatalogs(t, conn, prj.PublicId, 1)[0]
	set := TestSets(t, conn, c.PublicId, 1)[0]

	repo, err := NewRepository(ctx, rw, rw, kms)
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
	assert.Len(got, len(hosts))
	assert.Empty(cmp.Diff(hosts, got, opts...))
	assert.NoError(db.TestVerifyOplog(t, rw, set.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second)))

	// second call - add new set of hosts - should succeed
	set.Version = set.Version + 1
	Hosts := TestHosts(t, conn, c.PublicId, 5)
	var hostIds2 []string
	for _, h := range Hosts {
		hostIds2 = append(hostIds2, h.PublicId)
	}
	got2, err2 := repo.AddSetMembers(ctx, prj.PublicId, set.PublicId, set.Version, hostIds2)
	require.NoError(err2)
	require.NotNil(got2)

	hosts = append(hosts, Hosts...)
	assert.Len(got2, len(hosts))
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
	got3, err3 := repo.AddSetMembers(ctx, prj.PublicId, set.PublicId, set.Version, hostIds3)
	require.Error(err3)
	require.Nil(got3)
}

func TestRepository_DeleteSetMembers_Parameters(t *testing.T) {
	ctx := context.Background()
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
		projectId string
		setId     string
		version   uint32
		hostIds   []string
		opt       []Option
	}

	tests := []struct {
		name      string
		args      args
		want      int
		wantErr   bool
		wantIsErr errors.Code
	}{
		{
			name: "empty-project-id",
			args: args{
				setId:   set.PublicId,
				version: set.Version,
				hostIds: hostIds,
			},
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "empty-set-id",
			args: args{
				projectId: prj.PublicId,
				version:   set.Version,
				hostIds:   hostIds,
			},
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "zero-version",
			args: args{
				projectId: prj.PublicId,
				setId:     set.PublicId,
				hostIds:   hostIds,
			},
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "empty-host-ids",
			args: args{
				projectId: prj.PublicId,
				setId:     set.PublicId,
				version:   set.Version,
			},
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "invalid-version",
			args: args{
				projectId: prj.PublicId,
				setId:     set.PublicId,
				version:   badVersion,
				hostIds:   hostIds,
			},
			wantErr: true,
		},
		{
			name: "valid",
			args: args{
				projectId: prj.PublicId,
				setId:     set.PublicId,
				version:   set.Version,
				hostIds:   hostIds,
			},
			want:    count,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(ctx, rw, rw, kms)
			require.NoError(err)
			require.NotNil(repo)
			got, err := repo.DeleteSetMembers(ctx, tt.args.projectId, tt.args.setId, tt.args.version, tt.args.hostIds, tt.args.opt...)
			if tt.wantIsErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantIsErr), err), "want err: %q got: %q", tt.wantIsErr, err)
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

func TestRepository_DeleteSetMembers_Combinations(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)

	_, prj := iam.TestScopes(t, iamRepo)

	assert, require := assert.New(t), require.New(t)
	c := TestCatalogs(t, conn, prj.PublicId, 1)[0]
	set := TestSets(t, conn, c.PublicId, 1)[0]

	repo, err := NewRepository(ctx, rw, rw, kms)
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
	got, err := repo.DeleteSetMembers(ctx, prj.PublicId, set.PublicId, set.Version, idsA)
	assert.NoError(err)
	require.Equal(len(idsA), got)
	assert.NoError(db.TestVerifyOplog(t, rw, set.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_DELETE), db.WithCreateNotBefore(10*time.Second)))

	// verify hostsB are still members
	members, err := getHosts(ctx, repo.reader, set.PublicId, unlimited)
	require.NoError(err)

	opts := []cmp.Option{
		cmpopts.SortSlices(func(x, y *Host) bool { return x.PublicId < y.PublicId }),
		protocmp.Transform(),
	}
	assert.Len(members, len(hostsB))
	assert.Empty(cmp.Diff(hostsB, members, opts...))

	// second call - delete first half of hosts again - should fail
	set.Version = set.Version + 1
	got2, err2 := repo.DeleteSetMembers(ctx, prj.PublicId, set.PublicId, set.Version, idsA)
	require.Error(err2)
	assert.Zero(got2)

	// third call - delete first half and second half - should fail
	got3, err3 := repo.DeleteSetMembers(ctx, prj.PublicId, set.PublicId, set.Version, hostIds)
	require.Error(err3)
	assert.Zero(got3)

	// fourth call - delete second half of hosts - should succeed
	got4, err4 := repo.DeleteSetMembers(ctx, prj.PublicId, set.PublicId, set.Version, idsB)
	assert.NoError(err4)
	require.Equal(len(idsB), got4)
	assert.NoError(db.TestVerifyOplog(t, rw, set.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_DELETE), db.WithCreateNotBefore(10*time.Second)))

	// verify no members remain
	Members, err := getHosts(ctx, repo.reader, set.PublicId, unlimited)
	require.NoError(err)
	require.Empty(Members)
}

func TestRepository_SetSetMembers_Parameters(t *testing.T) {
	ctx := context.Background()
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

	// hostsA has the first 3 hosts, hostsB has the last 3 hosts
	// the middle host is shared in both.
	hostsA, hostsB := hosts[:3], hosts[2:]
	// hostsA is the initial set of hosts in the host set
	TestSetMembers(t, conn, set.PublicId, hostsA)

	var hostIds []string
	for _, h := range hostsB {
		hostIds = append(hostIds, h.PublicId)
	}

	badVersion := uint32(12345)

	type args struct {
		projectId string
		setId     string
		version   uint32
		hostIds   []string
		opt       []Option
	}

	tests := []struct {
		name      string
		args      args
		want      []*Host
		wantCount int
		wantErr   bool
		wantIsErr errors.Code
	}{
		{
			name: "empty-project-id",
			args: args{
				setId:   set.PublicId,
				version: set.Version,
				hostIds: hostIds,
			},
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "empty-set-id",
			args: args{
				projectId: prj.PublicId,
				version:   set.Version,
				hostIds:   hostIds,
			},
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "zero-version",
			args: args{
				projectId: prj.PublicId,
				setId:     set.PublicId,
				hostIds:   hostIds,
			},
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "invalid-version",
			args: args{
				projectId: prj.PublicId,
				setId:     set.PublicId,
				version:   badVersion,
				hostIds:   hostIds,
			},
			wantErr: true,
		},
		{
			name: "valid",
			args: args{
				projectId: prj.PublicId,
				setId:     set.PublicId,
				version:   set.Version,
				hostIds:   hostIds,
			},
			want:      hostsB,
			wantCount: 4, // 2 deleted, 2 added
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(ctx, rw, rw, kms)
			require.NoError(err)
			require.NotNil(repo)
			got, gotCount, err := repo.SetSetMembers(ctx, tt.args.projectId, tt.args.setId, tt.args.version, tt.args.hostIds, tt.args.opt...)
			if tt.wantIsErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantIsErr), err), "want err: %q got: %q", tt.wantIsErr, err)
				assert.Nil(got)
				assert.Equal(tt.wantCount, gotCount)
				assert.Error(db.TestVerifyOplog(t, rw, tt.args.setId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second)))
				return
			}
			if tt.wantErr {
				assert.Error(err)
				assert.Nil(got)
				assert.Equal(tt.wantCount, gotCount)
				assert.Error(db.TestVerifyOplog(t, rw, tt.args.setId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second)))
				return
			}
			require.NoError(err)
			opts := []cmp.Option{
				cmpopts.SortSlices(func(x, y *Host) bool { return x.PublicId < y.PublicId }),
				protocmp.Transform(),
			}
			assert.Equal(tt.wantCount, gotCount)
			assert.Len(got, len(tt.want))
			assert.Empty(cmp.Diff(tt.want, got, opts...))
			assert.NoError(db.TestVerifyOplog(t, rw, tt.args.setId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second)))
		})
	}
}

func TestRepository_SetSetMembers_Combinations(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)

	_, prj := iam.TestScopes(t, iamRepo)

	assert, require := assert.New(t), require.New(t)
	c := TestCatalogs(t, conn, prj.PublicId, 1)[0]
	set := TestSets(t, conn, c.PublicId, 1)[0]

	repo, err := NewRepository(ctx, rw, rw, kms)
	require.NoError(err)
	require.NotNil(repo)

	count := 5
	hosts := TestHosts(t, conn, c.PublicId, count)

	var hostIds []string
	for _, h := range hosts {
		hostIds = append(hostIds, h.PublicId)
	}

	// hostsA has the first 3 hosts, hostsB has the last 3 hosts
	// the middle host is shared in both.
	hostsA, hostsB := hosts[:3], hosts[2:]
	hostIdsA, hostIdsB := hostIds[:3], hostIds[2:]

	opts := []cmp.Option{
		cmpopts.SortSlices(func(x, y *Host) bool { return x.PublicId < y.PublicId }),
		protocmp.Transform(),
	}

	// first call - empty set, empty host Ids - no additions no deletions
	got1, gotCount1, err1 := repo.SetSetMembers(ctx, prj.PublicId, set.PublicId, set.Version, nil)
	assert.NoError(err1)
	assert.Empty(got1)
	assert.Zero(gotCount1)
	assert.Error(db.TestVerifyOplog(t, rw, set.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second)))

	// second call - all additions
	got2, gotCount2, err2 := repo.SetSetMembers(context.Background(), prj.PublicId, set.PublicId, set.Version, hostIdsA)
	assert.NoError(err2)
	assert.Equal(len(hostsA), gotCount2)
	assert.NoError(db.TestVerifyOplog(t, rw, set.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second)))
	assert.Len(got2, len(hostsA))
	assert.Empty(cmp.Diff(hostsA, got2, opts...))

	// third call - mix of additions and deletions
	set.Version = set.Version + 1
	got3, gotCount3, err3 := repo.SetSetMembers(ctx, prj.PublicId, set.PublicId, set.Version, hostIdsB)
	assert.NoError(err3)
	assert.Equal(4, gotCount3)
	assert.NoError(db.TestVerifyOplog(t, rw, set.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second)))
	assert.Len(got3, len(hostsB))
	assert.Empty(cmp.Diff(hostsB, got3, opts...))

	// fourth call - all deletions
	set.Version = set.Version + 1
	got4, gotCount4, err4 := repo.SetSetMembers(ctx, prj.PublicId, set.PublicId, set.Version, nil)
	assert.NoError(err4)
	assert.Equal(len(hostsB), gotCount4)
	assert.NoError(db.TestVerifyOplog(t, rw, set.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second)))
	assert.Empty(got4)
}

func TestRepository_changes(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)

	_, prj := iam.TestScopes(t, iamRepo)

	t.Run("all-additions", func(t *testing.T) {
		c := TestCatalogs(t, conn, prj.PublicId, 1)[0]
		set := TestSets(t, conn, c.PublicId, 1)[0]
		count := 5
		hosts := TestHosts(t, conn, c.PublicId, count)

		var hostIds []string
		for _, h := range hosts {
			hostIds = append(hostIds, h.PublicId)
		}

		var want []*change
		for _, h := range hosts {
			chg := &change{
				Action: "add",
				HostId: h.PublicId,
			}
			want = append(want, chg)
		}

		assert, require := assert.New(t), require.New(t)
		repo, err := NewRepository(ctx, rw, rw, kms)
		require.NoError(err)
		require.NotNil(repo)

		got, err := repo.changes(ctx, set.PublicId, hostIds)
		assert.NoError(err)
		require.NotNil(got)
		opts := []cmp.Option{
			cmpopts.SortSlices(func(x, y *change) bool { return x.HostId < y.HostId }),
		}
		assert.Len(got, len(want))
		assert.Empty(cmp.Diff(want, got, opts...))
	})
	t.Run("all-deletions", func(t *testing.T) {
		c := TestCatalogs(t, conn, prj.PublicId, 1)[0]
		set := TestSets(t, conn, c.PublicId, 1)[0]
		count := 5
		hosts := TestHosts(t, conn, c.PublicId, count)
		TestSetMembers(t, conn, set.PublicId, hosts)

		var want []*change
		for _, h := range hosts {
			chg := &change{
				Action: "delete",
				HostId: h.PublicId,
			}
			want = append(want, chg)
		}

		assert, require := assert.New(t), require.New(t)
		repo, err := NewRepository(ctx, rw, rw, kms)
		require.NoError(err)
		require.NotNil(repo)

		got, err := repo.changes(ctx, set.PublicId, nil)
		assert.NoError(err)
		require.NotNil(got)
		opts := []cmp.Option{
			cmpopts.SortSlices(func(x, y *change) bool { return x.HostId < y.HostId }),
		}
		assert.Len(got, len(want))
		assert.Empty(cmp.Diff(want, got, opts...))
	})
	t.Run("additions-with-deletions", func(t *testing.T) {
		c := TestCatalogs(t, conn, prj.PublicId, 1)[0]
		set := TestSets(t, conn, c.PublicId, 1)[0]

		count := 5
		hosts := TestHosts(t, conn, c.PublicId, count)
		initialHosts := hosts[:3]
		TestSetMembers(t, conn, set.PublicId, initialHosts)
		targetHosts := hosts[2:]
		deleteHosts := hosts[:2]
		insertHosts := hosts[3:]

		var targetHostIds []string
		for _, h := range targetHosts {
			targetHostIds = append(targetHostIds, h.PublicId)
		}

		var want []*change
		for _, h := range deleteHosts {
			chg := &change{
				Action: "delete",
				HostId: h.PublicId,
			}
			want = append(want, chg)
		}
		for _, h := range insertHosts {
			chg := &change{
				Action: "add",
				HostId: h.PublicId,
			}
			want = append(want, chg)
		}

		assert, require := assert.New(t), require.New(t)
		repo, err := NewRepository(ctx, rw, rw, kms)
		require.NoError(err)
		require.NotNil(repo)

		got, err := repo.changes(ctx, set.PublicId, targetHostIds)
		assert.NoError(err)
		require.NotNil(got)
		opts := []cmp.Option{
			cmpopts.SortSlices(func(x, y *change) bool { return x.HostId < y.HostId }),
		}
		assert.Len(got, len(want))
		assert.Empty(cmp.Diff(want, got, opts...))
	})
}
