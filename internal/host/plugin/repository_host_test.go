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
	hostplg "github.com/hashicorp/boundary/internal/plugin/host"
	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRepository_UpsertHosts(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	_, prj := iam.TestScopes(t, iamRepo)

	plg := hostplg.TestPlugin(t, conn, "create")
	plgm := map[string]plgpb.HostPluginServiceClient{
		plg.GetPublicId(): NewWrappingPluginClient(&plgpb.UnimplementedHostPluginServiceServer{}),
	}

	catalog := TestCatalog(t, conn, prj.PublicId, plg.GetPublicId())
	const setCount int = 3
	setIds := make([]string, 0, setCount)
	for i := 0; i < setCount; i++ {
		set := TestSet(t, conn, kms, catalog, plgm)
		setIds = append(setIds, set.GetPublicId())
	}
	phs, exp := TestExternalHosts(t, catalog, setIds, setCount)

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
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "no-external-id-hosts",
			in: func() *input {
				testPhs, _ := TestExternalHosts(t, catalog.GetPublicId(), setIds, setCount)
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
			name: "no-scope-id",
			in: func() *input {
				cat := catalog.clone()
				cat.ScopeId = ""
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
			name: "valid",
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

				ph.SetIds = ph.SetIds[0 : len(ph.SetIds)-1]
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
			repo, err := NewRepository(rw, rw, kms, plgm)
			require.NoError(err)
			require.NotNil(repo)
			in := tt.in()
			got, err := repo.UpsertHosts(ctx, in.catalog, in.sets, in.phs, tt.opts...)
			if tt.wantIsErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantIsErr), err), "want err: %q got: %q", tt.wantIsErr, err)
				assert.Nil(got)
				return
			}
			require.NoError(err, fmt.Sprintf("%v", in.catalog))
			require.NotNil(got)

			// Basic tests
			assert.Len(got, len(in.phs))
			assert.NoError(db.TestVerifyOplog(t, rw, in.catalog.GetPublicId(), db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second)))

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

			// Check again, but via performing an explicit list
			got, err = repo.ListHosts(ctx, in.catalog.GetPublicId())
			require.NoError(err)
			require.NotNil(got)
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

			// Now individually call read on each host
			for _, exp := range in.exp {
				got, err := repo.LookupHost(ctx, exp.GetPublicId())
				require.NoError(err)
				require.NotNil(got)
				assert.Empty(
					cmp.Diff(
						exp,
						got,
						cmpopts.IgnoreUnexported(Host{}, store.Host{}),
						cmpopts.IgnoreTypes(&timestamp.Timestamp{}),
					),
				)
			}
		})
	}
}
