// The MIT License (MIT)
//
// Original Work
// Copyright (c) 2016 Matthias Kadenbach
// https://github.com/mattes/migrate
//
// Modified Work
// Copyright (c) 2018 Dale Hui
// https://github.com/golang-migrate/migrate
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package postgres

import (
	"strconv"
	"strings"
	"testing"
)

func Test_computeLineFromPos(t *testing.T) {
	testcases := []struct {
		pos      int
		wantLine uint
		wantCol  uint
		input    string
		wantOk   bool
	}{
		{
			15, 2, 6, "SELECT *\nFROM foo", true, // foo table does not exists
		},
		{
			16, 3, 6, "SELECT *\n\nFROM foo", true, // foo table does not exists, empty line
		},
		{
			25, 3, 7, "SELECT *\nFROM foo\nWHERE x", true, // x column error
		},
		{
			27, 5, 7, "SELECT *\n\nFROM foo\n\nWHERE x", true, // x column error, empty lines
		},
		{
			10, 2, 1, "SELECT *\nFROMM foo", true, // FROMM typo
		},
		{
			11, 3, 1, "SELECT *\n\nFROMM foo", true, // FROMM typo, empty line
		},
		{
			17, 2, 8, "SELECT *\nFROM foo", true, // last character
		},
		{
			18, 0, 0, "SELECT *\nFROM foo", false, // invalid position
		},
	}
	for i, tc := range testcases {
		t.Run("tc"+strconv.Itoa(i), func(t *testing.T) {
			run := func(crlf bool, nonASCII bool) {
				var name string
				if crlf {
					name = "crlf"
				} else {
					name = "lf"
				}
				if nonASCII {
					name += "-nonascii"
				} else {
					name += "-ascii"
				}
				t.Run(name, func(t *testing.T) {
					input := tc.input
					if crlf {
						input = strings.Replace(input, "\n", "\r\n", -1)
					}
					if nonASCII {
						input = strings.Replace(input, "FROM", "FRÖM", -1)
					}
					gotLine, gotCol, gotOK := computeLineFromPos(input, tc.pos)

					if tc.wantOk {
						t.Logf("pos %d, want %d:%d, %#v", tc.pos, tc.wantLine, tc.wantCol, input)
					}

					if gotOK != tc.wantOk {
						t.Fatalf("expected ok %v but got %v", tc.wantOk, gotOK)
					}
					if gotLine != tc.wantLine {
						t.Fatalf("expected line %d but got %d", tc.wantLine, gotLine)
					}
					if gotCol != tc.wantCol {
						t.Fatalf("expected col %d but got %d", tc.wantCol, gotCol)
					}
				})
			}
			run(false, false)
			run(true, false)
			run(false, true)
			run(true, true)
		})
	}
}
