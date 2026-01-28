// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

// Package scheduler allows callers to register recurring jobs on the controller.  The scheduler
// will periodically query the repository for registered jobs that should be run.
//
// Before a job can be invoked by the scheduler, it must be made known to the scheduler
// by being registered on the instance of the scheduler that is running.
package scheduler
