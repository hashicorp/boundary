package static

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/host/static/store"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHostSetMember_New(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	conn.LogMode(false)
	wrapper := db.TestWrapper(t)

	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	cats := TestCatalogs(t, conn, prj.PublicId, 2)

	blueCat := cats[0]
	blueSets := testSets(t, conn, blueCat.GetPublicId(), 2)
	blueHosts := TestHosts(t, conn, blueCat.GetPublicId(), 2)

	// TODO(mgaffney) 05/2020:
	// these will be needed when the repository code is done
	// greenCat := cats[1]
	// greenSets := testSets(t, conn, greenCat.GetPublicId(), 2)
	// greenHosts := TestHosts(t, conn, greenCat.GetPublicId(), 2)

	var tests = []struct {
		name    string
		set     *HostSet
		host    *Host
		wantErr bool
	}{
		{
			name: "valid-host-in-set",
			set:  blueSets[0],
			host: blueHosts[0],
		},
		// {
		// 	name:    "invalid-diff-catalogs",
		// 	set:     greenSets[0],
		// 	host:    blueHosts[0],
		// 	wantErr: true,
		// },
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			got, err := NewHostSetMember(tt.set.PublicId, tt.host.PublicId)
			if tt.wantErr {
				assert.Error(err)
				assert.Nil(got)
			} else {
				assert.NoError(err)
				if assert.NotNil(got) {
					w := db.New(conn)
					err2 := w.Create(context.Background(), got)
					assert.NoError(err2)
				}
			}
		})
	}
}

func TestHostSetMember_SetTableName(t *testing.T) {
	defaultTableName := "static_host_set_member"
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
			def := &HostSetMember{
				HostSetMember: &store.HostSetMember{},
			}
			require.Equal(defaultTableName, def.TableName())
			s := &HostSetMember{
				HostSetMember: &store.HostSetMember{},
				tableName:     tt.initialName,
			}
			s.SetTableName(tt.setNameTo)
			assert.Equal(tt.want, s.TableName())
		})
	}
}
