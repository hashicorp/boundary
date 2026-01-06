// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

// Package billing provides usage numbers that can be used for
// billing purposes. The currently supported metric is monthly
// active users. A user is considered active within a month
// if they have at least one issued auth token within the time
// range of the start and end of a given month.
package billing
