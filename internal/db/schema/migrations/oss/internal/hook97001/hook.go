// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package hook97001

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/hashicorp/boundary/internal/db/schema/migration"
)

var RepairDescription = `Removes redundant grant scopes from roles. Descendants and Children grant scopes grant permissions to
multiple scopes which may overlap with individually granted scopes. Any individually granted scopes that have already been
covered by 'descendants' or 'children' grants are considered invalid and are removed`

type invalidAssociation struct {
	RoleId               string `db:"role_id"`
	RoleScopeId          string `db:"role_scope_id"`
	CoveredByGrantScope  string `db:"covered_by_grant_scope"`
	IndividualGrantScope string `db:"individual_grant_scope"`
}

func (e *invalidAssociation) problemString() string {
	return fmt.Sprintf(`Role '%s' in scope '%s' has the '%s' grant scope which covers '%s'`,
		e.RoleId, e.RoleScopeId, e.CoveredByGrantScope, e.IndividualGrantScope)
}

func (e *invalidAssociation) repairString() string {
	return fmt.Sprintf(`Remove redundant grant scopes '%s' association from role '%s' in scope '%s' because it overlaps with '%s'`,
		e.IndividualGrantScope, e.RoleId, e.RoleScopeId, e.CoveredByGrantScope)
}

// FindInvalidAssociations executes a query to identify invalid associations between
// roles and overlapping grant scopes.
// roles in global scope
//   - 'descendants' covers all individual scope so any individual grant scope is invalid if a role already has 'descendants' grant scope
//   - 'children' covers all org scopes so any individual org grant scope is invalid if a role already has 'children' grant scope
//
// roles in org scope
//   - 'children' covers all projects the org owns. Any individually project grant scope when role already has 'children' grant scope is invalid
//
// It returns migration.Problems if
// any invalid associations were found; nil if no invalid associations were found
// or an error. Implements the CheckFunc definition from the migration package.
//
// An example of a migration problem:
// Role 'r_orgaa___97001' in scope 'o_ta___97001' has 'children' grant scope which covers 'p_pA___97001'
func FindInvalidAssociations(ctx context.Context, tx *sql.Tx) (migration.Problems, error) {
	if tx == nil {
		return nil, fmt.Errorf("query to get invalid associations failed: missing transaction")
	}
	invalidAssociations, err := query(ctx, tx, getInvalidGrantsAssociationsQuery)
	if err != nil {
		return nil, fmt.Errorf("query to get invalid associations failed: %v", err)
	}
	if len(invalidAssociations) > 0 {
		var problems migration.Problems
		for _, ia := range invalidAssociations {
			problems = append(problems, ia.problemString())
		}
		return problems, nil
	}
	return nil, nil
}

// RepairInvalidAssociations executes a query to remove redundant grant scopes from roles.
// Redundant grant scopes are individual scopes assigned to roles that are already granted the same permissions by broader, special grant scopes
// ['children', 'descendants']. These broader grant scopes automatically include permissions to the individual
// scopes, making the individual assignments unnecessary.
//
// It returns migration.Repairs if any redundant grant scopes were removed, nil if none were found, or an error.
// Implements the RepairFunc definition from the migration package.
//
// Example migration repair message:
// "Remove redundant grant scopes 'o_ta___97001' association from role 'r_globala_97001' in scope 'global' because it overlaps with 'descendants'"
func RepairInvalidAssociations(ctx context.Context, tx *sql.Tx) (migration.Repairs, error) {
	if tx == nil {
		return nil, fmt.Errorf("query to delete invalid grants associations failed: missing transaction")
	}
	invalid, err := query(ctx, tx, deleteInvalidGrantsAssociationsQuery)
	if err != nil {
		return nil, fmt.Errorf("query to delete invalid grants associations failed: %v", err)
	}
	if len(invalid) > 0 {
		var repairs migration.Repairs
		for _, ia := range invalid {
			repairs = append(repairs, ia.repairString())
		}
		return repairs, nil
	}
	return nil, nil
}

func query(ctx context.Context, tx *sql.Tx, query string) ([]invalidAssociation, error) {
	rows, err := tx.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	invalid := make([]invalidAssociation, 0)
	for rows.Next() {
		var r invalidAssociation
		if err := rows.Scan(&r.RoleId, &r.RoleScopeId, &r.CoveredByGrantScope, &r.IndividualGrantScope); err != nil {
			return nil, err
		}
		invalid = append(invalid, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return invalid, nil
}
