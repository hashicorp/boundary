package iam

import (
	"context"
	"os"
	"reflect"
	"testing"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/watchtower/internal/db"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
)

func Test_NewUser(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer cleanup()
	assert := assert.New(t)
	defer conn.Close()

	t.Run("valid", func(t *testing.T) {
		w := db.New(conn)
		s, err := NewOrganization()
		assert.NoError(err)
		assert.True(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.NoError(err)
		assert.True(s.PublicId != "")

		user, err := NewUser(s.PublicId)
		assert.NoError(err)
		assert.True(user.User != nil)
		assert.Equal(user.ScopeId, s.PublicId)
	})
}

func Test_UserCreate(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer cleanup()
	assert := assert.New(t)
	defer conn.Close()

	t.Run("valid-user", func(t *testing.T) {
		w := db.New(conn)
		s, err := NewOrganization()
		assert.Equal(s.Type, OrganizationScope.String())
		assert.NoError(err)
		assert.True(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.NoError(err)
		assert.True(s.PublicId != "")

		user, err := NewUser(s.PublicId)
		assert.NoError(err)
		err = w.Create(context.Background(), user)
		assert.NoError(err)
		assert.True(user.PublicId != "")
	})
}

func Test_UserGetScope(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer cleanup()
	assert := assert.New(t)
	defer conn.Close()
	t.Run("valid scope", func(t *testing.T) {
		w := db.New(conn)
		s, err := NewOrganization()
		assert.NoError(err)
		assert.True(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.NoError(err)
		assert.True(s.PublicId != "")

		user, err := NewUser(s.PublicId)
		assert.NoError(err)
		err = w.Create(context.Background(), user)
		assert.NoError(err)
		assert.True(user.PublicId != "")
		assert.Equal(user.ScopeId, s.PublicId)

		childScope, err := NewProject(s.PublicId)
		assert.NoError(err)
		assert.True(childScope.Scope != nil)
		assert.Equal(childScope.GetParentId(), s.PublicId)
		err = w.Create(context.Background(), childScope)
		assert.NoError(err)

		user.ScopeId = s.PublicId
		rowsUpdated, err := w.Update(context.Background(), user, []string{"ScopeId"})
		assert.NoError(err)
		assert.Equal(1, rowsUpdated)

		scope, err := user.GetScope(context.Background(), w)
		assert.NoError(err)
		assert.True(scope != nil)
		assert.Equal(scope.PublicId, user.ScopeId)
	})

}

func Test_UserGroups(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer cleanup()
	assert := assert.New(t)
	defer conn.Close()

	t.Run("valid", func(t *testing.T) {
		w := db.New(conn)
		s, err := NewOrganization()
		assert.NoError(err)
		assert.True(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.NoError(err)
		assert.True(s.PublicId != "")

		user, err := NewUser(s.PublicId)
		assert.NoError(err)
		err = w.Create(context.Background(), user)
		assert.NoError(err)

		grp, err := NewGroup(s.PublicId, WithDescription("this is a test group"))
		assert.NoError(err)
		assert.True(grp != nil)
		assert.Equal(grp.Description, "this is a test group")
		assert.Equal(s.PublicId, grp.ScopeId)
		err = w.Create(context.Background(), grp)
		assert.NoError(err)
		assert.True(grp.PublicId != "")

		gm, err := NewGroupMember(grp, user)
		assert.NoError(err)
		assert.True(gm != nil)
		err = w.Create(context.Background(), gm)
		assert.NoError(err)

		group, err := user.Groups(context.Background(), w)
		assert.NoError(err)
		assert.Equal(len(group), 1)
		assert.Equal(group[0].PublicId, grp.PublicId)
	})
}

func Test_UserRoles(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer cleanup()
	assert := assert.New(t)
	defer conn.Close()

	t.Run("valid", func(t *testing.T) {
		w := db.New(conn)
		s, err := NewOrganization()
		assert.NoError(err)
		assert.True(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.NoError(err)
		assert.True(s.PublicId != "")

		user, err := NewUser(s.PublicId)
		assert.NoError(err)
		err = w.Create(context.Background(), user)
		assert.NoError(err)

		role, err := NewRole(s.PublicId, WithDescription("this is a test role"))
		assert.NoError(err)
		assert.True(role != nil)
		assert.Equal(role.Description, "this is a test role")
		assert.Equal(s.PublicId, role.ScopeId)
		err = w.Create(context.Background(), role)
		assert.NoError(err)
		assert.True(role.PublicId != "")

		uRole, err := NewAssignedRole(role, user)
		assert.NoError(err)
		assert.True(uRole != nil)
		assert.Equal(uRole.GetRoleId(), role.PublicId)
		assert.Equal(uRole.GetPrincipalId(), user.PublicId)
		err = w.Create(context.Background(), uRole)
		assert.NoError(err)
		assert.True(uRole != nil)
		assert.Equal(uRole.GetPrincipalId(), user.PublicId)

		userRoles, err := user.Roles(context.Background(), w)
		assert.NoError(err)
		assert.Equal(len(userRoles), 1)
		assert.Equal(userRoles[role.PublicId].GetPublicId(), role.PublicId)
	})
}

func Test_UserGrants(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer cleanup()
	assert := assert.New(t)
	defer conn.Close()

	t.Run("valid", func(t *testing.T) {
		if len(os.Getenv("DEBUG")) != 0 {
			// turn on debugging
			conn.LogMode(true)
		}
		id, err := uuid.GenerateUUID()
		assert.NoError(err)
		w := db.New(conn)
		s, err := NewOrganization()
		assert.NoError(err)
		assert.True(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.NoError(err)
		assert.True(s.PublicId != "")

		role, err := NewRole(s.PublicId)
		assert.NoError(err)
		assert.True(role != nil)
		assert.Equal(s.PublicId, role.ScopeId)
		err = w.Create(context.Background(), role)
		assert.NoError(err)
		assert.True(role.PublicId != "")

		g, err := NewRoleGrant(role, "everything*"+id)
		assert.NoError(err)
		assert.True(g != nil)
		assert.Equal(g.RoleId, role.PublicId)
		assert.Equal(g.Grant, "everything*"+id)
		err = w.Create(context.Background(), g)
		assert.NoError(err)
		assert.True(g.PublicId != "")

		user, err := NewUser(s.PublicId)
		assert.NoError(err)
		err = w.Create(context.Background(), user)
		assert.NoError(err)
		uRole, err := NewAssignedRole(role, user)
		assert.NoError(err)
		assert.True(uRole != nil)
		assert.Equal(uRole.GetRoleId(), role.PublicId)
		assert.Equal(uRole.GetPrincipalId(), user.PublicId)
		err = w.Create(context.Background(), uRole)
		assert.NoError(err)
		assert.True(uRole != nil)
		assert.Equal(uRole.GetPrincipalId(), user.PublicId)

		userGrants, err := user.Grants(context.Background(), w)
		assert.NoError(err)
		assert.Equal(len(userGrants), 1)
		assert.Equal(userGrants[0].GetPublicId(), g.PublicId)

		grp, err := NewGroup(s.PublicId, WithDescription("user grants test group"))
		assert.NoError(err)
		assert.True(grp != nil)
		assert.Equal(grp.Description, "user grants test group")
		assert.Equal(s.PublicId, grp.ScopeId)
		err = w.Create(context.Background(), grp)
		assert.NoError(err)
		assert.True(grp.PublicId != "")

		gm, err := NewGroupMember(grp, user)
		assert.NoError(err)
		assert.True(gm != nil)
		err = w.Create(context.Background(), gm)
		assert.NoError(err)

		groupRole, err := NewRole(s.PublicId)
		assert.NoError(err)
		assert.True(role != nil)
		assert.Equal(s.PublicId, groupRole.ScopeId)
		err = w.Create(context.Background(), groupRole)
		assert.NoError(err)
		assert.True(groupRole.PublicId != "")

		groupGrant, err := NewRoleGrant(groupRole, "group-grant*"+id)
		assert.NoError(err)
		assert.True(groupGrant != nil)
		assert.Equal(groupGrant.RoleId, groupRole.PublicId)
		assert.Equal(groupGrant.Grant, "group-grant*"+id)
		err = w.Create(context.Background(), groupGrant)
		assert.NoError(err)
		assert.True(groupGrant.PublicId != "")

		gRole, err := NewAssignedRole(groupRole, grp)
		assert.NoError(err)
		assert.True(gRole != nil)
		assert.Equal(gRole.GetRoleId(), groupRole.PublicId)
		assert.Equal(gRole.GetPrincipalId(), grp.PublicId)
		err = w.Create(context.Background(), gRole)
		assert.NoError(err)
		assert.True(gRole != nil)
		assert.Equal(gRole.GetPrincipalId(), grp.PublicId)

		allGrants, err := user.Grants(context.Background(), w, WithGroupGrants(true))
		assert.NoError(err)
		assert.Equal(len(allGrants), 2)
		for _, grant := range allGrants {
			assert.True(grant.PublicId == g.PublicId || grant.PublicId == groupGrant.PublicId)
		}
	})
}
func TestUser_Clone(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer cleanup()
	assert := assert.New(t)
	defer conn.Close()

	t.Run("valid", func(t *testing.T) {
		w := db.New(conn)
		s, err := NewOrganization()
		assert.NoError(err)
		assert.True(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.NoError(err)
		assert.True(s.PublicId != "")

		user, err := NewUser(s.PublicId)
		assert.NoError(err)
		err = w.Create(context.Background(), user)
		assert.NoError(err)

		cp := user.Clone()
		assert.True(proto.Equal(cp.(*User).User, user.User))
	})
	t.Run("not-equal", func(t *testing.T) {
		w := db.New(conn)
		s, err := NewOrganization()
		assert.NoError(err)
		assert.True(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.NoError(err)
		assert.True(s.PublicId != "")

		user, err := NewUser(s.PublicId)
		assert.NoError(err)
		err = w.Create(context.Background(), user)
		assert.NoError(err)

		user2, err := NewUser(s.PublicId)
		assert.NoError(err)
		err = w.Create(context.Background(), user2)
		assert.NoError(err)

		cp := user.Clone()
		assert.True(!proto.Equal(cp.(*User).User, user2.User))
	})
}

func TestNewUser(t *testing.T) {
	type args struct {
		organizationPublicId string
		opt                  []Option
	}
	tests := []struct {
		name    string
		args    args
		want    *User
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewUser(tt.args.organizationPublicId, tt.args.opt...)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewUser() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewUser() = %v, want %v", got, tt.want)
			}
		})
	}
}
