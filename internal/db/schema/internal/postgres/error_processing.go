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

import "strings"

const newLine = '\n'

func runesCount(input []rune, target rune) int {
	var count int
	for _, r := range input {
		if r == target {
			count++
		}
	}
	return count
}

func runesLastIndex(input []rune, target rune) int {
	for i := len(input) - 1; i >= 0; i-- {
		if input[i] == target {
			return i
		}
	}
	return -1
}

func computeLineFromPos(s string, pos int) (line uint, col uint, ok bool) {
	// replace crlf with lf
	s = strings.Replace(s, "\r\n", "\n", -1)
	// pg docs: pos uses index 1 for the first character, and positions are measured in characters not bytes
	runes := []rune(s)
	if pos > len(runes) {
		return 0, 0, false
	}
	sel := runes[:pos]
	line = uint(runesCount(sel, newLine) + 1)
	col = uint(pos - 1 - runesLastIndex(sel, newLine))
	return line, col, true
}
