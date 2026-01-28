// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"context"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/scheduler"
	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
)

// RegisterJobs registers plugin host related jobs with the provided scheduler.
func RegisterJobs(ctx context.Context, scheduler *scheduler.Scheduler, r db.Reader, w db.Writer, kms *kms.Kms, plgm map[string]plgpb.HostPluginServiceClient) error {
	const op = "plugin.RegisterJobs"
	setSyncJob, err := newSetSyncJob(ctx, r, w, kms, plgm)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	if err = scheduler.RegisterJob(ctx, setSyncJob); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("set sync job"))
	}
	orphanedHostCleanupJob, err := newOrphanedHostCleanupJob(ctx, r, w, kms)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	if err = scheduler.RegisterJob(ctx, orphanedHostCleanupJob); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("orphaned host cleanup job"))
	}

	return nil
}
