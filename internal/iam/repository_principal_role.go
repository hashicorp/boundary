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
	newUserRoles := make([]interface{}, 0, len(userIds))
	for _, id := range userIds {
		userRoles, err := NewUserRole(roleId, id)
		if err != nil {
			panic(err.Error())
		}
		newUserRoles = append(newUserRoles, userRoles)
	}
	newGrpRoles := make([]PrincipalRole, 0, len(groupIds))
	for _, id := range groupIds {
		grpRole, err := NewGroupRole(roleId, id)
		if err != nil {
			panic(err.Error())
		}
		newGrpRoles = append(newGrpRoles, grpRole)
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
	resultPrincipalRoles := make([]PrincipalRole, 0, len(userIds)+len(groupIds))
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			w.CreateItems(ctx, newUserRoles)
			// for _, principalRole := range newPrincipalRoles {
			// 	returnedPrincipalRole := principalRole.Clone()
			// 	err := w.Create(
			// 		ctx,
			// 		returnedPrincipalRole,
			// 		db.WithOplog(r.wrapper, metadata),
			// 	)
			// 	if err != nil {
			// 		if db.IsUniqueError(err) {
			// 			return fmt.Errorf("add principal role: unable to add principal %s to role %s : %w", principalRole.GetPrincipalId(), roleId, db.ErrNotUnique)
			// 		}
			// 		return fmt.Errorf("add principal role: %w when attempting to add principal %s to role %s", err, principalRole.GetPrincipalId(), roleId)
			// 	}
			// 	resultPrincipalRoles = append(resultPrincipalRoles, returnedPrincipalRole.(PrincipalRole))
			// }
			return nil
		},
	)
	if err != nil {
		return nil, err
	}
	return resultPrincipalRoles, nil
}

func (r *Repository) SetPrincipalRoles(ctx context.Context, roleId string, userIds, groupIds []string, opt ...Option) ([]*PrincipalRole, int, error) {
	panic("not implemented")
}

func (r *Repository) LookupPrincipalRoles(ctx context.Context, roleId string) ([]*PrincipalRole, error) {
	// see role_assigned_role.go for query
	panic("not implemented")
}
func (r *Repository) DeletePrincipalRoles(ctx context.Context, roleId string, userIds, groupIds []string, opt ...Option) (int, error) {
	panic("not implemented")
}
