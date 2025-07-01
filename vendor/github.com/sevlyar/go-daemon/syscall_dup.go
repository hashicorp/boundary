//go:build (!linux || !arm64) && (!linux || !riscv64) && !windows && go1.7
// +build !linux !arm64
// +build !linux !riscv64
// +build !windows
// +build go1.7

package daemon

import "golang.org/x/sys/unix"

func syscallDup(oldfd int, newfd int) (err error) {
	return unix.Dup2(oldfd, newfd)
}
