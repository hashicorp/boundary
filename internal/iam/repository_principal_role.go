package iam

import (
	"context"
	"fmt"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/oplog"
)

func (r *Repository) AddPrincipalRoles(ctx context.Context, roleId string, userIds, groupIds []string, opt ...Option) ([]PrincipalRole, error) {
	if roleId == "" {
		return nil, fmt.Errorf("add principal role: missing role id %w", db.ErrInvalidParameter)
	}
	if len(userIds) == 0 && len(groupIds) == 0 {
		return nil, fmt.Errorf("add principal roles: missing either user or groups to add %w", db.ErrInvalidParameter)
	}
	newPrincipalRoles := make([]PrincipalRole, 0, len(userIds)+len(groupIds))
	for _, id := range userIds {
		userRole, err := NewUserRole(roleId, id)
		if err != nil {
			panic(err.Error())
		}
		newPrincipalRoles = append(newPrincipalRoles, userRole)
	}
	for _, id := range groupIds {
		grpRole, err := NewGroupRole(roleId, id)
		if err != nil {
			panic(err.Error())
		}
		newPrincipalRoles = append(newPrincipalRoles, grpRole)
	}
	role := allocRole()
	role.PublicId = roleId
	scope, err := role.GetScope(ctx, r.reader)
	if err != nil {
		return nil, fmt.Errorf("add principal roles: unable to get role %s scope to create metadata: %w", roleId, err)
	}
	metadata := oplog.Metadata{
		"op-type":                      []string{oplog.OpType_OP_TYPE_CREATE.String()},
		"scope-id":                     []string{scope.PublicId},
		"scope-type":                   []string{scope.Type},
		"aggregate-resource-public-id": []string{roleId},
	}
	// rawDB, err := r.writer.DB()
	// gdb, err := gorm.Open("postgres", rawDB)
	// ticketer, err := oplog.NewGormTicketer(gdb, oplog.WithAggregateNames(true))
	// ticket, err := ticketer.GetTicket(allocRole().tableName)

	resultPrincipalRoles := make([]PrincipalRole, 0, len(userIds)+len(groupIds))
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(w db.Writer) error {
			for _, principalRole := range newPrincipalRoles {
				returnedPrincipalRole := principalRole.Clone()
				err := w.Create(
					ctx,
					returnedPrincipalRole,
					db.WithOplog(r.wrapper, metadata),
				)
				if err != nil {
					if db.IsUniqueError(err) {
						return fmt.Errorf("add principal role: unable to add principal %s to role %s : %w", principalRole.GetPrincipalId(), roleId, db.ErrNotUnique)
					}
					return fmt.Errorf("add principal role: %w when attempting to add principal %s to role %s", err, principalRole.GetPrincipalId(), roleId)
				}
				resultPrincipalRoles = append(resultPrincipalRoles, returnedPrincipalRole.(PrincipalRole))
			}
			return nil
		},
	)
	if err != nil {
		return nil, err
	}
	return resultPrincipalRoles, nil
}

func (r *Repository) SetPrincipalRoles(ctx context.Context, roleId string, userIds []string, opt ...Option) ([]*PrincipalRole, int, error) {
	panic("not implemented")
}

func (r *Repository) LookupPrincipalRoles(ctx context.Context, roleId string) ([]*PrincipalRole, error) {
	// see role_assigned_role.go for query
	panic("not implemented")
}
func (r *Repository) DeleteUserRoles(ctx context.Context, roleId string, userIds []string, opt ...Option) (int, error) {
	panic("not implemented")
}
