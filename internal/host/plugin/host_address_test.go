// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/host"
	"github.com/hashicorp/boundary/internal/host/store"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHostDnsName_Create(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	w := db.New(conn)
	wrapper := db.TestWrapper(t)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	plg := plugin.TestPlugin(t, conn, "test")
	cat := TestCatalog(t, conn, prj.PublicId, plg.GetPublicId())
	host1 := TestHost(t, conn, cat.GetPublicId(), "external")

	type args struct {
		hostId string
		name   string
	}

	tests := []struct {
		name        string
		args        args
		want        *host.DnsName
		wantNewErr  bool
		skipNewFunc bool
		wantDbErr   bool
	}{
		{
			name: "blank-host-id-validate",
			args: args{
				hostId: "",
				name:   "foo.bar.com",
			},
			wantNewErr: true,
		},
		{
			name: "blank-name-validate",
			args: args{
				hostId: host1.GetPublicId(),
				name:   "",
			},
			wantNewErr: true,
		},
		{
			name: "blank-host-id-db",
			args: args{
				name: "foo.bar.com",
			},
			skipNewFunc: true,
			wantDbErr:   true,
		},
		{
			name: "blank-name-db",
			args: args{
				hostId: host1.GetPublicId(),
			},
			skipNewFunc: true,
			wantDbErr:   true,
		},
		{
			name: "valid",
			args: args{
				hostId: host1.GetPublicId(),
				name:   "foo.bar.com",
			},
			want: &host.DnsName{
				DnsName: &store.DnsName{
					HostId: host1.GetPublicId(),
					Name:   "foo.bar.com",
				},
			},
		},
		{
			name: "duplicate-name",
			args: args{
				hostId: host1.GetPublicId(),
				name:   "foo.bar.com",
			},
			want: &host.DnsName{
				DnsName: &store.DnsName{
					HostId: host1.GetPublicId(),
					Name:   "foo.bar.com",
				},
			},
			wantDbErr: true,
		},
		{
			name: "valid-second",
			args: args{
				hostId: host1.GetPublicId(),
				name:   "baz.bar.com",
			},
			want: &host.DnsName{
				DnsName: &store.DnsName{
					HostId: host1.GetPublicId(),
					Name:   "baz.bar.com",
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			require := require.New(t)
			var got *host.DnsName
			var err error
			if !tt.skipNewFunc {
				got, err = host.NewDnsName(ctx, tt.args.hostId, tt.args.name)
				if tt.wantNewErr {
					require.Error(err)
					return
				}
				require.NoError(err)
				require.Equal(tt.want, got)
			} else {
				got = &host.DnsName{
					DnsName: &store.DnsName{
						HostId: tt.args.hostId,
						Name:   tt.args.name,
					},
				}
			}

			require.NotNil(got)
			err = w.Create(ctx, got)
			if tt.wantDbErr {
				require.Error(err)
				return
			}
			require.NoError(err)
		})
	}
}

func TestHostIpAddress_Create(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	w := db.New(conn)
	wrapper := db.TestWrapper(t)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	plg := plugin.TestPlugin(t, conn, "test")
	cat := TestCatalog(t, conn, prj.PublicId, plg.GetPublicId())
	host1 := TestHost(t, conn, cat.GetPublicId(), "external")

	type args struct {
		hostId  string
		address string
	}

	tests := []struct {
		name        string
		args        args
		want        *host.IpAddress
		wantNewErr  bool
		skipNewFunc bool
		wantDbErr   bool
	}{
		{
			name: "blank-host-id-validate",
			args: args{
				hostId:  "",
				address: "1.2.3.4",
			},
			wantNewErr: true,
		},
		{
			name: "blank-name-validate",
			args: args{
				hostId:  host1.GetPublicId(),
				address: "",
			},
			wantNewErr: true,
		},
		{
			name: "bad-address-validate",
			args: args{
				hostId:  host1.GetPublicId(),
				address: "foo.bar.com",
			},
			wantNewErr: true,
		},
		{
			name: "blank-host-id-db",
			args: args{
				address: "1.2.3.4",
			},
			skipNewFunc: true,
			wantDbErr:   true,
		},
		{
			name: "blank-address-db",
			args: args{
				hostId: host1.GetPublicId(),
			},
			skipNewFunc: true,
			wantDbErr:   true,
		},
		{
			name: "valid-ipv4",
			args: args{
				hostId:  host1.GetPublicId(),
				address: "1.2.3.4",
			},
			want: &host.IpAddress{
				IpAddress: &store.IpAddress{
					HostId:  host1.GetPublicId(),
					Address: "1.2.3.4",
				},
			},
		},
		{
			name: "valid-ipv6",
			args: args{
				hostId:  host1.GetPublicId(),
				address: "2001:4860:4860:0:0:0:0:8888",
			},
			want: &host.IpAddress{
				IpAddress: &store.IpAddress{
					HostId:  host1.GetPublicId(),
					Address: "2001:4860:4860:0:0:0:0:8888",
				},
			},
		},
		{
			name: "valid-abbreviated-ipv6",
			args: args{
				hostId:  host1.GetPublicId(),
				address: "2001:4860:4860::8887",
			},
			want: &host.IpAddress{
				IpAddress: &store.IpAddress{
					HostId:  host1.GetPublicId(),
					Address: "2001:4860:4860::8887",
				},
			},
		},
		{
			name: "invalid-abbreviated-[ipv6]",
			args: args{
				hostId:  host1.GetPublicId(),
				address: "[2001:4860:4860::8886]",
			},
			wantNewErr: true,
		},
		{
			name: "invalid-[ipv6]",
			args: args{
				hostId:  host1.GetPublicId(),
				address: "[2001:4860:4860:0:0:0:0:8885]",
			},
			wantNewErr: true,
		},
		{
			name: "invalid-abbreviated-[ipv6]:port",
			args: args{
				hostId:  host1.GetPublicId(),
				address: "[2001:4860:4860::8884]:80",
			},
			wantNewErr: true,
		},
		{
			name: "invalid-[ipv6]:port",
			args: args{
				hostId:  host1.GetPublicId(),
				address: "[2001:4860:4860:0:0:0:0:8883]:80",
			},
			wantNewErr: true,
		},
		{
			name: "duplicate-name",
			args: args{
				hostId:  host1.GetPublicId(),
				address: "1.2.3.4",
			},
			want: &host.IpAddress{
				IpAddress: &store.IpAddress{
					HostId:  host1.GetPublicId(),
					Address: "1.2.3.4",
				},
			},
			wantDbErr: true,
		},
		{
			name: "valid-second",
			args: args{
				hostId:  host1.GetPublicId(),
				address: "2.3.4.5",
			},
			want: &host.IpAddress{
				IpAddress: &store.IpAddress{
					HostId:  host1.GetPublicId(),
					Address: "2.3.4.5",
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			require := require.New(t)
			var got *host.IpAddress
			var err error
			if !tt.skipNewFunc {
				got, err = host.NewIpAddress(ctx, tt.args.hostId, tt.args.address)
				if tt.wantNewErr {
					require.Error(err)
					return
				}
				require.NoError(err)
				require.Equal(tt.want, got)
			} else {
				got = &host.IpAddress{
					IpAddress: &store.IpAddress{
						HostId:  tt.args.hostId,
						Address: tt.args.address,
					},
				}
			}

			require.NotNil(got)
			err = w.Create(ctx, got)
			if tt.wantDbErr {
				require.Error(err)
				return
			}
			require.NoError(err)
		})
	}
}

func TestHostDnsName_Delete(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	w := db.New(conn)
	wrapper := db.TestWrapper(t)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	plg := plugin.TestPlugin(t, conn, "test")
	cat := TestCatalog(t, conn, prj.PublicId, plg.GetPublicId())
	host1 := TestHost(t, conn, cat.GetPublicId(), "external")
	addr1, err := host.NewDnsName(ctx, host1.GetPublicId(), "addr1.foo.com")
	require.NoError(t, err)
	require.NoError(t, w.Create(ctx, addr1))

	type args struct {
		hostId string
		name   string
	}

	tests := []struct {
		name       string
		args       args
		wantDelete bool
		wantError  bool
	}{
		{
			name: "wrong_host_id",
			args: args{
				hostId: "something",
				name:   addr1.GetName(),
			},
		},
		{
			name: "valid",
			args: args{
				hostId: addr1.GetHostId(),
				name:   addr1.GetName(),
			},
			wantDelete: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got := &host.DnsName{
				DnsName: &store.DnsName{
					HostId: tt.args.hostId,
					Name:   tt.args.name,
				},
			}
			require.NoError(t, err)
			require.NotNil(t, got)
			k, err := w.Delete(ctx, got)
			if tt.wantError {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			if tt.wantDelete {
				assert.Equal(t, 1, k)
			} else {
				assert.Equal(t, 0, k)
			}
		})
	}
}

func TestHostIpAddress_Delete(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	w := db.New(conn)
	wrapper := db.TestWrapper(t)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	plg := plugin.TestPlugin(t, conn, "test")
	cat := TestCatalog(t, conn, prj.PublicId, plg.GetPublicId())
	host1 := TestHost(t, conn, cat.GetPublicId(), "external")
	addr1, err := host.NewIpAddress(ctx, host1.GetPublicId(), "1.2.3.4")
	require.NoError(t, err)
	require.NoError(t, w.Create(ctx, addr1))

	type args struct {
		hostId  string
		address string
	}

	tests := []struct {
		name       string
		args       args
		wantDelete bool
		wantError  bool
	}{
		{
			name: "wrong_host_id",
			args: args{
				hostId:  "something",
				address: addr1.GetAddress(),
			},
		},
		{
			name: "valid",
			args: args{
				hostId:  addr1.GetHostId(),
				address: addr1.GetAddress(),
			},
			wantDelete: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got := &host.IpAddress{
				IpAddress: &store.IpAddress{
					HostId:  tt.args.hostId,
					Address: tt.args.address,
				},
			}
			require.NoError(t, err)
			require.NotNil(t, got)
			k, err := w.Delete(ctx, got)
			if tt.wantError {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			if tt.wantDelete {
				assert.Equal(t, 1, k)
			} else {
				assert.Equal(t, 0, k)
			}
		})
	}
}
