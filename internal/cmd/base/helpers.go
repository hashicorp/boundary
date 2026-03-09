// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package base

import (
	"strings"

	"github.com/kr/text"
)

// WrapAtLengthWithPadding wraps the given text at the maxLineLength, taking
// into account any provided left padding.
func WrapAtLengthWithPadding(s string, pad int) string {
	wrapped := text.Wrap(s, maxLineLength-pad)
	lines := strings.Split(wrapped, "\n")
	for i, line := range lines {
		lines[i] = strings.Repeat(" ", pad) + line
	}
	return strings.Join(lines, "\n")
}

// WrapAtLength wraps the given text to maxLineLength.
func WrapAtLength(s string) string {
	return WrapAtLengthWithPadding(s, 0)
}
