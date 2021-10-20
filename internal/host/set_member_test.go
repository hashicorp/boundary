package host_test

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/host"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/host/store"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestSetMember_Insert(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)

	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	cats := static.TestCatalogs(t, conn, prj.PublicId, 2)

	blueCat := cats[0]
	blueSets := static.TestSets(t, conn, blueCat.GetPublicId(), 1)
	blueHosts := static.TestHosts(t, conn, blueCat.GetPublicId(), 1)

	greenCat := cats[1]
	greenSets := static.TestSets(t, conn, greenCat.GetPublicId(), 1)

	tests := []struct {
		name    string
		set     *static.HostSet
		host    *static.Host
		wantErr bool
	}{
		{
			name: "valid-host-in-set",
			set:  blueSets[0],
			host: blueHosts[0],
		},
		{
			name:    "invalid-diff-catalogs",
			set:     greenSets[0],
			host:    blueHosts[0],
			wantErr: true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := host.NewSetMember(tt.set.PublicId, tt.host.PublicId)
			require.NoError(err)
			require.NotNil(got)
			w := db.New(conn)
			err2 := w.Create(context.Background(), got)
			if tt.wantErr {
				assert.Error(err2)
				return
			}
			assert.NoError(err2)
		})
	}
}

func TestSetMember_SetTableName(t *testing.T) {
	defaultTableName := "host_set_member"
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
			def := &host.SetMember{
				SetMember: &store.SetMember{},
			}
			require.Equal(defaultTableName, def.TableName())
			s := &host.SetMember{
				SetMember: &store.SetMember{},
			}
			s.SetTableName(tt.initialName)
			if tt.initialName == "" {
				assert.Equal(defaultTableName, s.TableName())
			} else {
				assert.Equal(tt.initialName, s.TableName())
			}
			s.SetTableName(tt.setNameTo)
			assert.Equal(tt.want, s.TableName())
		})
	}
}

func TestHostSetMember_ImmutableFields(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	w := db.New(conn)
	wrapper := db.TestWrapper(t)

	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	cat := static.TestCatalogs(t, conn, prj.PublicId, 1)[0]
	sets := static.TestSets(t, conn, cat.GetPublicId(), 1)
	hosts := static.TestHosts(t, conn, cat.GetPublicId(), 1)

	new, err := host.NewSetMember(sets[0].PublicId, hosts[0].PublicId)
	require.NoError(t, err)
	err = w.Create(context.Background(), new)
	assert.NoError(t, err)

	tests := []struct {
		name      string
		update    *host.SetMember
		fieldMask []string
	}{
		{
			name: "set_id",
			update: func() *host.SetMember {
				c := new.Clone()
				c.HostId = "shs_thisIsNotAValidId"
				return c
			}(),
			fieldMask: []string{"SetId"},
		},
		{
			name: "host_id",
			update: func() *host.SetMember {
				c := new.Clone()
				c.HostId = "hst_01234567890"
				return c
			}(),
			fieldMask: []string{"HostId"},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			orig := new.Clone()
			err = w.LookupWhere(context.Background(), orig, "host_id = ? and set_id = ?", orig.HostId, orig.SetId)
			require.NoError(err)

			rowsUpdated, err := w.Update(context.Background(), tt.update, tt.fieldMask, nil, db.WithSkipVetForWrite(true))
			require.Error(err)
			assert.Equal(0, rowsUpdated)

			after := new.Clone()
			err = w.LookupWhere(context.Background(), after, "host_id = ? and set_id = ?", after.HostId, after.SetId)
			require.NoError(err)

			assert.True(proto.Equal(orig, after))
		})
	}
}
