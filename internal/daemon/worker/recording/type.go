// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package recording

// pauseReason type is used by the pause and resume methods of the
// RecordingManager interface to determine when to pause and resume recording.
// The pause() method should be called with a pauseReason type that accurately
// describes the reason why the recording manager is being paused.
// The resume() method should be called with the same pauseReason type only
// when the caller can definitely state that all places that called pause() no
// longer need the recorder manager to be paused.
type pauseReason uint8

const (
	// unknown is the default value for PauseReason
	// This should not be used as a reason to pause the recording manager.
	// This is solely used to for testing purposes.
	unknown pauseReason = iota

	// localStorageException is used to pause the recording manager when
	// there is an exception with the local storage.
	localStorageException pauseReason = iota
)
