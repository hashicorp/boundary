// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package hook96007

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/hashicorp/boundary/internal/db/schema/migration"
)

var RepairDescription = `Removes redundant grant scopes from roles. Descendants and Children grant scopes grant permissions to
multiple scopes which may overlap with individually granted scopes. Any individually granted scopes that have already been 
covered by 'descendants' or 'children' grants are considered illegal and are removed`

type illegalAssociation struct {
	RoleId               string `db:"role_id"`
	RoleScopeId          string `db:"role_scope_id"`
	CoveredByGrantScope  string `db:"covered_by_grant_scope"`
	IndividualGrantScope string `db:"individual_grant_scope"`
}

func (e *illegalAssociation) problemString() string {
	return fmt.Sprintf(`Role '%s' in scope '%s' has the '%s' grant scope which covers '%s'`,
		e.RoleId, e.RoleScopeId, e.CoveredByGrantScope, e.IndividualGrantScope)
}

func (e *illegalAssociation) repairString() string {
	return fmt.Sprintf(`Remove redundant grant scopes '%s' association from role '%s' in scope '%s' because it overlaps with '%s'`,
		e.IndividualGrantScope, e.RoleId, e.RoleScopeId, e.CoveredByGrantScope)
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
// Role 'r_orgaa___96007' in scope 'o_ta___96007' has 'children' grant scope which covers 'p_pA___96007'
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

// RepairIllegalAssociations executes a query to remove redundant grant scopes from roles.
//
// Redundant grant scopes are individual scopes assigned to roles that are already granted the same permissions by broader, special grant scopes
// ['children', 'descendants']. These broader grant scopes automatically include permissions to the individual
// scopes, making the individual assignments unnecessary.
//
// It returns migration.Repairs if any redundant grant scopes were removed, nil if none were found, or an error.
// Implements the RepairFunc definition from the migration package.
//
// Example migration repair message:
// "Remove redundant grant scopes 'o_ta___96007' association from role 'r_globala_96007' in scope 'global' because it overlaps with 'descendants'"
func RepairIllegalAssociations(ctx context.Context, tx *sql.Tx) (migration.Repairs, error) {
	if tx == nil {
		return nil, fmt.Errorf("query to delete illegal associations failed: missing transaction")
	}
	illegalAssociations, err := query(ctx, tx, deleteIllegalAssociationsQuery)
	if err != nil {
		return nil, fmt.Errorf("query to delete illegal associations failed: %v", err)
	}
	if len(illegalAssociations) > 0 {
		var repairs migration.Repairs
		for _, ia := range illegalAssociations {
			repairs = append(repairs, ia.repairString())
		}
		return repairs, nil
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
		if err := rows.Scan(&r.RoleId, &r.RoleScopeId, &r.CoveredByGrantScope, &r.IndividualGrantScope); err != nil {
			return nil, err
		}
		illegalAssociations = append(illegalAssociations, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return illegalAssociations, nil
}
