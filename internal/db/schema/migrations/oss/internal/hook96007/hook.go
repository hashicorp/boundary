package hook96007

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/hashicorp/boundary/internal/db/schema/migration"
)

var RepairDescription = `Removes redundant grants from roles' grant scopes. For Descendants and Children already grants permissions to 
individual scopes which may overlap with individually granted scopes. Any individually grant scopes that have already been 
covered by Descendants or Children grant is considered illegal and will be removed`

type illegalAssociation struct {
	RoleId                string `db:"role_id"`
	RoleScopeId           string `db:"role_scope_id"`
	SpecialGrantScope     string `db:"special_grant_scope"`
	IndividualGrantScopes string `db:"individual_grant_scope"`
}

func (e illegalAssociation) problemString() string {
	const message = `Role '%s' in scope '%s' has ['%s'] grant scope which covers [%s]`
	return fmt.Sprintf(message, e.RoleId, e.RoleScopeId, e.SpecialGrantScope, e.IndividualGrantScopes)
}

// FindIllegalAssociations executes a query to identify illegal associations between
// roles and overlapping grant scopes.
// roles in global scope
//   - 'descendants' covers all individual scope so any individual grant scope is illegal if a role already has 'descendants' grant scope
//   - 'children' covers all org scopes so any individual org grant scope is illegal if a role already has 'children' grant scope
//
// roles in org scope
//   - 'children' covers all projects the org owns. Any individually project grant scope when role already has 'children' grant scope is illegal
//
// It returns migration.Problems if
// any illegal associations were found; nil if no illegal associations were found
// or an error. Implements the CheckFunc definition from the migration package.
//
// An example of a migration problem:
// "Role r... in scope .... in org o_A has an illegal association to host set hsst_A in host catalog hsct_A in project p_B in org o_A"
func FindIllegalAssociations(ctx context.Context, tx *sql.Tx) (migration.Problems, error) {
	if tx == nil {
		return nil, fmt.Errorf("query to get illegal associations failed: missing transaction")
	}
	illegalAssociations, err := query(ctx, tx, getIllegalAssociationsQuery)
	if err != nil {
		return nil, fmt.Errorf("query to get illegal associations failed: %v", err)
	}
	if len(illegalAssociations) > 0 {
		var problems migration.Problems
		for _, ia := range illegalAssociations {
			problems = append(problems, ia.problemString())
		}
		return problems, nil
	}
	return nil, nil
}

func query(ctx context.Context, tx *sql.Tx, query string) ([]illegalAssociation, error) {
	rows, err := tx.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	illegalAssociations := make([]illegalAssociation, 0)
	for rows.Next() {
		var r illegalAssociation
		if err := rows.Scan(&r.RoleId, &r.RoleScopeId, &r.SpecialGrantScope, &r.IndividualGrantScopes); err != nil {
			return nil, err
		}
		illegalAssociations = append(illegalAssociations, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return illegalAssociations, nil
}

func RepairIllegalAssociations(ctx context.Context, tx *sql.Tx) (migration.Repairs, error) {
	panic("not implemented")
}
