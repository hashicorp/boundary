package iam

import "context"

func AddPrincipalRoles(ctx context.Context, roleId string, userIds, groupIds []string, opt ...Option) ([]*PrincipalRole, error) {
	panic("not implemented")
}

func SetPrincipalRoles(ctx context.Context, roleId string, userIds []string, opt ...Option) ([]*PrincipalRole, int, error) {
	panic("not implemented")
}

func LookupPrincipalRoles(ctx context.Context, roleId string) ([]*PrincipalRole, error) {
	panic("not implemented")
}
func DeleteUserRoles(ctx context.Context, roleId string, userIds []string, opt ...Option) (int, error) {
	panic("not implemented")
}
