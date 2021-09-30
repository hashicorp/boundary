//go:build windows
// +build windows

package cmd

// MakeSigUSR2Ch does nothing useful on Windows.
func MakeSigUSR2Ch() chan struct{} {
	return make(chan struct{})
}
