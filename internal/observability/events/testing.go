package event

import (
	"sync"
	"testing"
)

var testSysEventerLock sync.Mutex

func testResetSystEventer(t *testing.T) {
	t.Helper()
	testSysEventerLock.Lock()
	defer testSysEventerLock.Unlock()
	sysEventerOnce = sync.Once{}
	sysEventer = nil
}
