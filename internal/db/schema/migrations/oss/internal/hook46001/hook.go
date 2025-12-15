// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

// Package hook46001 implements the hook CheckFunc & RepairFunc definitions for CVE-2022-36130.
//
// The check functionality reports illegal associations between a target and a resource
// (static credential, credential library, & host set).
// An illegal association is defined by a target & resource not
// belonging to the same project scope.
//
// The repair functionality removes all illegal associations and returns a report.
package hook46001

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/hashicorp/boundary/internal/db/schema/migration"
)

type illegalAssociation struct {
	TargetId          string
	TargetProjectId   string
	TargetOrgId       string
	ResourceType      string
	ResourceId        string
	ResourceParentId  string
	ResourceProjectId string
	ResourceOrgId     string
}

func (a *illegalAssociation) resourceParentType() string {
	switch a.ResourceType {
	case "credential library", "static credential":
		return "credential store"
	case "host set":
		return "host catalog"
	default:
		return "unknown"
	}
}

func (a *illegalAssociation) problemString() string {
	return fmt.Sprintf("Target %s in project %s in org %s has an illegal association to %s %s in %s %s in project %s in org %s",
		a.TargetId, a.TargetProjectId, a.TargetOrgId,
		a.ResourceType, a.ResourceId,
		a.resourceParentType(), a.ResourceParentId,
		a.ResourceProjectId, a.ResourceOrgId)
}

func (a *illegalAssociation) repairString() string {
	return fmt.Sprintf("Removed illegal association from target %s in project %s in org %s to %s %s in %s %s in project %s in org %s",
		a.TargetId, a.TargetProjectId, a.TargetOrgId,
		a.ResourceType, a.ResourceId,
		a.resourceParentType(), a.ResourceParentId,
		a.ResourceProjectId, a.ResourceOrgId)
}

var RepairDescription = `Removes illegal associations from targets. A target can only contain
associations to host sources and credential sources belonging to the same
project scope as the target. Any association between a target and a host
source or a credential source from a different project scope is considered
illegal and is removed.`

// FindIllegalAssociations executes a query to identify illegal associations between
// a target and a resource (static credential, credential library, & host set).
// An illegal association is defined as the target & resource not
// belonging to the same project scope. It returns migration.Problems if
// any illegal associations were found; nil if no illegal associations were found
// or an error. Implements the CheckFunc definition from the migration package.
//
// An example of a migration problem:
// "Target ttcp_A in project p_A in org o_A has an illegal association to host set hsst_A in host catalog hsct_A in project p_B in org o_A"
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

// RepairIllegalAssociations executes a query to remove illegal associations between
// a target and a resource (static credential, credential library, & host set).
// An illegal association defined as the target & resource not belonging to the same project scope.
// It returns migration.Repairs if any illegal associations were removed; nil if no illegal
// associations were found or an error. Implements the RepairFunc definition from
// the migration package.
//
// An example of a migration repair:
// "Removed illegal association from target ttcp_A in project p_A in org o_A to host set hsst_A in host catalog hsct_A in project p_B in org o_A"
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
		if err := rows.Scan(&r.ResourceType, &r.TargetId, &r.TargetProjectId, &r.TargetOrgId, &r.ResourceId, &r.ResourceParentId, &r.ResourceProjectId, &r.ResourceOrgId); err != nil {
			return nil, err
		}
		illegalAssociations = append(illegalAssociations, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return illegalAssociations, nil
}
