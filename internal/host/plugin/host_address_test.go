package plugin

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/host/plugin/store"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/plugin/host"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHostDnsAddress_Create(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	w := db.New(conn)
	wrapper := db.TestWrapper(t)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	plg := host.TestPlugin(t, conn, "test")
	cat := TestCatalog(t, conn, prj.PublicId, plg.GetPublicId())
	host1 := testHost(t, conn, cat.GetPublicId(), "external")

	type args struct {
		hostId string
		address string
	}

	tests := []struct {
		name    string
		args    args
		want    *HostDnsAddress
		wantErr bool
	}{
		{
			name: "blank-host-id",
			args: args{
				hostId: "",
				address:   "foo.bar.com",
			},
			want: &HostDnsAddress{HostAddress: &store.HostAddress{
				Address: "foo.bar.com",
			}},
			wantErr: true,
		},
		{
			name: "blank-address",
			args: args{
				hostId: host1.GetPublicId(),
			},
			want: &HostDnsAddress{HostAddress: &store.HostAddress{
				HostId: host1.GetPublicId(),
			}},
			wantErr: true,
		},
		{
			name: "valid",
			args: args{
				hostId: host1.GetPublicId(),
				address:   "valid.bar.com",
			},
			want: &HostDnsAddress{
				HostAddress: &store.HostAddress{
					HostId: host1.GetPublicId(),
					Address:   "valid.bar.com",
				},
			},
		},
		{
			name: "dupicate",
			args: args{
				hostId: host1.GetPublicId(),
				address:   "valid.bar.com",
			},
			want: &HostDnsAddress{
				HostAddress: &store.HostAddress{
					HostId: host1.GetPublicId(),
					Address:   "valid.bar.com",
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got := newHostDnsAddress(ctx, tt.args.hostId, tt.args.address)
			require.NotNil(t, got)
			assert.Equal(t, tt.want, got)

			err := w.Create(ctx, got)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHostIpAddress_Create(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	w := db.New(conn)
	wrapper := db.TestWrapper(t)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	plg := host.TestPlugin(t, conn, "test")
	cat := TestCatalog(t, conn, prj.PublicId, plg.GetPublicId())
	host1 := testHost(t, conn, cat.GetPublicId(), "external")

	type args struct {
		hostId string
		address string
	}

	tests := []struct {
		name    string
		args    args
		want    *HostIpAddress
		wantErr bool
	}{
		{
			name: "blank-host-id",
			args: args{
				hostId: "",
				address:   "10.0.0.4",
			},
			want: &HostIpAddress{HostAddress: &store.HostAddress{
				Address: "10.0.0.4",
			}},
			wantErr: true,
		},
		{
			name: "blank-address",
			args: args{
				hostId: host1.GetPublicId(),
			},
			want: &HostIpAddress{HostAddress: &store.HostAddress{
				HostId: host1.GetPublicId(),
			}},
			wantErr: true,
		},
		{
			name: "not-ip-address",
			args: args{
				hostId: host1.GetPublicId(),
				address: "not an ip address",
			},
			want: &HostIpAddress{HostAddress: &store.HostAddress{
				HostId: host1.GetPublicId(),
				Address: "not an ip address",
			}},
			wantErr: true,
		},
		{
			name: "valid",
			args: args{
				hostId: host1.GetPublicId(),
				address:   "10.0.0.4",
			},
			want: &HostIpAddress{
				HostAddress: &store.HostAddress{
					HostId: host1.GetPublicId(),
					Address:   "10.0.0.4",
				},
			},
		},
		{
			name: "dupicate",
			args: args{
				hostId: host1.GetPublicId(),
				address:   "10.0.0.4",
			},
			want: &HostIpAddress{
				HostAddress: &store.HostAddress{
					HostId: host1.GetPublicId(),
					Address:   "10.0.0.4",
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got := newHostIpAddress(ctx, tt.args.hostId, tt.args.address)
			require.NotNil(t, got)
			assert.Equal(t, tt.want, got)

			err := w.Create(ctx, got)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestHostDnsAddress_Delete(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	w := db.New(conn)
	wrapper := db.TestWrapper(t)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	plg := host.TestPlugin(t, conn, "test")
	cat := TestCatalog(t, conn, prj.PublicId, plg.GetPublicId())
	host1 := testHost(t, conn, cat.GetPublicId(), "external")
	addr1 := newHostDnsAddress(ctx, host1.GetPublicId(), "addr1.foo.com")
	require.NoError(t, w.Create(ctx, addr1))

	type args struct {
		hostId string
		address string
	}

	tests := []struct {
		name    string
		args       args
		wantDelete bool
	}{
		{
			name: "wrong_host_id",
			args: args{
				hostId: "something",
				address:   addr1.GetAddress(),
			},
		},
		{
			name: "wrong_address",
			args: args{
				hostId: addr1.GetHostId(),
				address: "wrong.foo.bar",
			},
		},
		{
			name: "valid",
			args: args{
				hostId: addr1.GetHostId(),
				address:   addr1.GetAddress(),
			},
			wantDelete: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got := newHostDnsAddress(ctx, tt.args.hostId, tt.args.address)
			require.NotNil(t, got)
			k, err := w.Delete(ctx, got)
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
	plg := host.TestPlugin(t, conn, "test")
	cat := TestCatalog(t, conn, prj.PublicId, plg.GetPublicId())
	host1 := testHost(t, conn, cat.GetPublicId(), "external")
	addr1 := newHostIpAddress(ctx, host1.GetPublicId(), "10.0.0.1")
	require.NoError(t, w.Create(ctx, addr1))

	type args struct {
		hostId string
		address string
	}

	tests := []struct {
		name    string
		args       args
		wantDelete bool
	}{
		{
			name: "wrong_host_id",
			args: args{
				hostId: "something",
				address:   addr1.GetAddress(),
			},
		},
		{
			name: "wrong_address",
			args: args{
				hostId: addr1.GetHostId(),
				address: "192.168.1.1",
			},
		},
		{
			name: "valid",
			args: args{
				hostId: addr1.GetHostId(),
				address:   addr1.GetAddress(),
			},
			wantDelete: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got := newHostIpAddress(ctx, tt.args.hostId, tt.args.address)
			require.NotNil(t, got)
			k, err := w.Delete(ctx, got)
			require.NoError(t, err)
			if tt.wantDelete {
				assert.Equal(t, 1, k)
			} else {
				assert.Equal(t, 0, k)
			}
		})
	}
}

func TestHostDnsAddress_SetTableName(t *testing.T) {
	defaultTableName := "host_plugin_host_dns_address"
	tests := []struct {
		name        string
		initialName string
		setNameTo   string
		want        string
	}{
		{
			name:        "new-name",
			initialName: "",
			setNameTo:   "new-name",
			want:        "new-name",
		},
		{
			name:        "reset to default",
			initialName: "initial",
			setNameTo:   "",
			want:        defaultTableName,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			def := allocHostDnsAddress()
			require.Equal(defaultTableName, def.TableName())
			s := &HostDnsAddress{
				HostAddress:      &store.HostAddress{},
				tableName: tt.initialName,
			}
			s.SetTableName(tt.setNameTo)
			assert.Equal(tt.want, s.TableName())
		})
	}
}

func TestHostIpAddress_SetTableName(t *testing.T) {
	defaultTableName := "host_plugin_host_ip_address"
	tests := []struct {
		name        string
		initialName string
		setNameTo   string
		want        string
	}{
		{
			name:        "new-name",
			initialName: "",
			setNameTo:   "new-name",
			want:        "new-name",
		},
		{
			name:        "reset to default",
			initialName: "initial",
			setNameTo:   "",
			want:        defaultTableName,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			def := allocHostIpAddress()
			require.Equal(defaultTableName, def.TableName())
			s := &HostIpAddress{
				HostAddress: &store.HostAddress{},
				tableName:   tt.initialName,
			}
			s.SetTableName(tt.setNameTo)
			assert.Equal(tt.want, s.TableName())
		})
	}
}
