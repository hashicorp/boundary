// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package mql

type stack[T any] struct {
	data []T
}

func (s *stack[T]) push(v T) {
	s.data = append(s.data, v)
}

func (s *stack[T]) pop() (T, bool) {
	var x T
	if len(s.data) > 0 {
		x, s.data = s.data[len(s.data)-1], s.data[:len(s.data)-1]
		return x, true
	}
	return x, false
}

func (s *stack[T]) clear() {
	s.data = nil
}

func (s *stack[T]) len() int {
	return len(s.data)
}

func runesToString(s stack[rune]) string {
	return string(s.data)
}
