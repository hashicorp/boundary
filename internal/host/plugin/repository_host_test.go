// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1


package plugin

import (
	"context"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/host/plugin/store"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/plugin"
	"github.com/hashicorp/boundary/internal/plugin/loopback"
	plgstore "github.com/hashicorp/boundary/internal/plugin/store"
	"github.com/hashicorp/boundary/internal/scheduler"
	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJob_UpsertHosts(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	sched := scheduler.TestScheduler(t, conn, wrapper)
	kms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	_, prj := iam.TestScopes(t, iamRepo)

	plg := plugin.TestPlugin(t, conn, "create")
	plgm := map[string]plgpb.HostPluginServiceClient{
		plg.GetPublicId(): loopback.NewWrappingPluginHostClient(&plgpb.UnimplementedHostPluginServiceServer{}),
	}

	catalog := TestCatalog(t, conn, prj.PublicId, plg.GetPublicId())
	const setCount int = 3
	setIds := make([]string, 0, setCount)
	for i := 0; i < setCount; i++ {
		set := TestSet(t, conn, kms, sched, catalog, plgm)
		setIds = append(setIds, set.GetPublicId())
	}
	sort.Strings(setIds)
	phs, exp := TestExternalHosts(t, catalog, setIds, setCount)
	phs[2].Name = phs[0].Name
	exp[2].Name = exp[0].Name

	type input struct {
		catalog *HostCatalog
		sets    []string
		phs     []*plgpb.ListHostsResponseHost
		exp     []*Host
	}

	tests := []struct {
		name      string
		in        func() *input
		opts      []Option
		wantIsErr errors.Code
	}{
		{
			name: "nil-hosts",
			in: func() *input {
				return &input{
					catalog: catalog,
					sets:    setIds,
				}
			},
		},
		{
			name: "no-external-id-hosts",
			in: func() *input {
				testPhs, _ := TestExternalHosts(t, catalog, setIds, setCount)
				testPhs[1].ExternalId = ""
				return &input{
					catalog: catalog,
					sets:    setIds,
					phs:     testPhs,
				}
			},
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "nil-catalog",
			in: func() *input {
				return &input{
					sets: setIds,
					phs:  phs,
				}
			},
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "no-catalog-id",
			in: func() *input {
				cat := catalog.clone()
				cat.PublicId = ""
				return &input{
					catalog: cat,
					sets:    setIds,
					phs:     phs,
				}
			},
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "no-project-id",
			in: func() *input {
				cat := catalog.clone()
				cat.ProjectId = ""
				return &input{
					catalog: cat,
					sets:    setIds,
					phs:     phs,
				}
			},
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "nil-sets",
			in: func() *input {
				return &input{
					catalog: catalog,
					phs:     phs,
				}
			},
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "no-sets",
			in: func() *input {
				return &input{
					catalog: catalog,
					sets:    make([]string, 0),
					phs:     phs,
				}
			},
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "valid", // Note: this also tests duplicate names
			in: func() *input {
				return &input{
					catalog: catalog,
					sets:    setIds,
					phs:     phs,
					exp:     exp,
				}
			},
		},
		{
			name: "valid-changed-values",
			in: func() *input {
				ph := phs[1]
				e := exp[1]
				newIp := testGetIpAddress(t)
				newName := testGetDnsName(t)
				ph.IpAddresses = append(ph.IpAddresses, newIp)
				e.IpAddresses = append(e.IpAddresses, newIp)
				ph.DnsNames = append(ph.DnsNames, newName)
				e.DnsNames = append(e.DnsNames, newName)
				// These are sorted by the repo function, so we need to match
				sort.Strings(e.IpAddresses)
				sort.Strings(e.DnsNames)

				ph.Name, ph.Description = ph.Description, ph.Name
				e.Name, e.Description = e.Description, e.Name

				ph.SetIds = ph.SetIds[0 : len(ph.SetIds)-1]
				e.SetIds = e.SetIds[0 : len(e.SetIds)-1]
				e.Version++
				return &input{
					catalog: catalog,
					sets:    setIds,
					phs:     phs,
					exp:     exp,
				}
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			job, err := newSetSyncJob(ctx, rw, rw, kms, plgm)
			require.NoError(err)
			require.NotNil(job)
			in := tt.in()
			got, err := job.upsertAndCleanHosts(ctx, in.catalog, in.sets, in.phs, tt.opts...)
			if tt.wantIsErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantIsErr), err), "want err: %q got: %q", tt.wantIsErr, err)
				assert.Nil(got)
				return
			}
			require.NoError(err, fmt.Sprintf("%v", in.catalog))

			// Basic tests
			assert.Len(got, len(in.phs))
			for _, h := range in.exp {
				assert.NoError(db.TestVerifyOplog(t, rw, h.GetPublicId(), db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second)))
			}

			// Make sure outputs match. Ignore timestamps.
			assert.Empty(
				cmp.Diff(
					in.exp,
					got,
					cmpopts.IgnoreUnexported(Host{}, store.Host{}),
					cmpopts.IgnoreTypes(&timestamp.Timestamp{}),
					cmpopts.SortSlices(func(x, y *Host) bool {
						return x.GetPublicId() < y.GetPublicId()
					}),
				),
			)

			repo, err := NewRepository(ctx, rw, rw, kms, sched, plgm)
			require.NoError(err)
			require.NotNil(repo)

			// Check again, but via performing an explicit list
			var gotPlg *plugin.Plugin
			got, gotPlg, err = repo.ListHostsByCatalogId(ctx, in.catalog.GetPublicId())
			require.NoError(err)
			assert.Len(got, len(in.phs))
			assert.Empty(
				cmp.Diff(
					in.exp,
					got,
					cmpopts.IgnoreUnexported(Host{}, store.Host{}),
					cmpopts.IgnoreTypes(&timestamp.Timestamp{}),
					cmpopts.SortSlices(func(x, y *Host) bool {
						return x.GetPublicId() < y.GetPublicId()
					}),
				),
			)
			plg := plg
			if len(in.phs) == 0 {
				plg = nil
			}
			assert.Empty(
				cmp.Diff(
					plg,
					gotPlg,
					cmpopts.IgnoreUnexported(plugin.Plugin{}, plgstore.Plugin{}),
					cmpopts.IgnoreTypes(&timestamp.Timestamp{}),
				),
			)

			// Now individually call read on each host, cache the matching set
			// IDs, and then check membership
			setIdMap := make(map[string][]string)
			for _, exp := range in.exp {
				for _, setId := range exp.SetIds {
					setIdMap[setId] = append(setIdMap[setId], exp.GetPublicId())
				}
				got, gotPlg, err := repo.LookupHost(ctx, exp.GetPublicId())
				require.NoError(err)
				require.NotNil(got)
				assert.NotEmpty(got.SetIds)
				assert.Empty(
					cmp.Diff(
						exp,
						got,
						cmpopts.IgnoreUnexported(Host{}, store.Host{}),
						cmpopts.IgnoreTypes(&timestamp.Timestamp{}),
					),
				)
				assert.Empty(
					cmp.Diff(
						plg,
						gotPlg,
						cmpopts.IgnoreUnexported(plugin.Plugin{}, plgstore.Plugin{}),
						cmpopts.IgnoreTypes(&timestamp.Timestamp{}),
					),
				)
			}
			for setId, expHostIds := range setIdMap {
				got, err = repo.ListHostsBySetIds(ctx, []string{setId})
				require.NoError(err)
				var gotHostIds []string
				for _, h := range got {
					gotHostIds = append(gotHostIds, h.GetPublicId())
				}
				assert.ElementsMatch(expHostIds, gotHostIds)
			}
		})
	}
}
