// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1


package checksum

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

const (
	sha256sumSep       = "  "
	sha256sumBinarySep = " *"
	sha256HexLength    = 64
)

// Sha256Sums is a map of file names with their corresponding SHA256SUM.
type Sha256Sums map[string][]byte

// LoadSha256Sums reads from an io.Reader to populate the Sha256Sums map The
// reader is expected to return the sums in a format that is compatible with
// sha256sum, that is each line should contain the hex encoded sum followed by
// a separator and then the file name. The separator should either be two
// spaces ("  ") or a space an asterisks (" *"). The former indicates a text
// file and the later a binary file. However, there is no difference between
// these for GNU systems. Therefore this also makes no distinction between the
// separators and checks for either.
//
// See: https://man7.org/linux/man-pages/man1/sha256sum.1.html
func LoadSha256Sums(r io.Reader) (Sha256Sums, error) {
	const op = "checksum.LoadSha256Sums"

	s := make(Sha256Sums)
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		var sum, file string
		var ok bool
		sum, file, ok = strings.Cut(scanner.Text(), sha256sumSep)
		if !ok {
			sum, file, ok = strings.Cut(scanner.Text(), sha256sumBinarySep)
		}
		if !ok {
			return nil, fmt.Errorf("%s: improperly formated line", op)
		}

		if len(sum) != sha256HexLength {
			return nil, fmt.Errorf("%s: improperly formated line", op)
		}

		if _, dup := s[file]; dup {
			return nil, fmt.Errorf("%s: duplicate file", op)
		}

		s[file] = []byte(sum)
	}

	return s, nil
}

// Sum returns the sum for the provided file, or an error if there is no sum.
func (s Sha256Sums) Sum(f string) ([]byte, error) {
	const op = "checksum.(Sha256Sums).Sum"

	sum, ok := s[f]
	if !ok {
		return nil, fmt.Errorf("%s: no sum for file %s", op, f)
	}

	return sum, nil
}
