// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package storage

const KB uint64 = 1024

// LogicalBlockSize represents a single logical address, which is equivalent to 4,096 bytes (4 KiB)
//
// A logical block is the minimum block that any file can allocate. Large files consist of multiple blocks.
// More information can be found here: https://en.wikipedia.org/wiki/Logical_block_addressing
const LogicalBlockSize = 4 * KB
