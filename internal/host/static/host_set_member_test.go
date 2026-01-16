// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

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

func TestHostSetMember_Insert(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)

	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	cats := TestCatalogs(t, conn, prj.PublicId, 2)

	blueCat := cats[0]
	blueSets := TestSets(t, conn, blueCat.GetPublicId(), 1)
	blueHosts := TestHosts(t, conn, blueCat.GetPublicId(), 1)

	greenCat := cats[1]
	greenSets := TestSets(t, conn, greenCat.GetPublicId(), 1)

	tests := []struct {
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
			got, err := NewHostSetMember(ctx, tt.set.PublicId, tt.host.PublicId)
			require.NoError(err)
			require.NotNil(got)
			w := db.New(conn)
			err2 := w.Create(ctx, got)
			if tt.wantErr {
				assert.Error(err2)
				return
			}
			assert.NoError(err2)
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
