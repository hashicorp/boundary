// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package recording

import "time"

// InfinityTS is the max protobuf timestamp value of 9999-12-31T23:59:59.999999999Z. It is
// used to represent an infinite retention value in session recording.
var InfinityTS = time.Date(9999, time.December, 31, 23, 23, 23, 1e9-1, time.UTC)
