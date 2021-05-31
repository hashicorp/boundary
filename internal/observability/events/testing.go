package event

import (
	"io/ioutil"
	"os"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

var testSysEventerLock sync.Mutex

func testResetSystEventer(t *testing.T) {
	t.Helper()
	testSysEventerLock.Lock()
	defer testSysEventerLock.Unlock()
	sysEventerOnce = sync.Once{}
	sysEventer = nil
}

type TestConfig struct {
	EventerConfig EventerConfig
	AllEvents     *os.File
	ErrorEvents   *os.File
}

func TestEventerConfig(t *testing.T, testName string) TestConfig {
	t.Helper()
	require := require.New(t)
	tmpAllFile, err := ioutil.TempFile("./", "tmp-observations-"+testName)
	require.NoError(err)

	tmpErrFile, err := ioutil.TempFile("./", "tmp-errors-"+testName)
	require.NoError(err)

	return TestConfig{
		EventerConfig: EventerConfig{
			ObservationsEnabled: true,
			ObservationDelivery: Enforced,
			AuditEnabled:        true,
			AuditDelivery:       Enforced,
			Sinks: []SinkConfig{
				{
					Name:       "every-type-file-sink",
					EventTypes: []Type{EveryType},
					Format:     JSONSinkFormat,
					Path:       "./",
					FileName:   tmpAllFile.Name(),
				},
				{
					Name:       "stdout",
					EventTypes: []Type{EveryType},
					Format:     JSONSinkFormat,
					SinkType:   StdoutSink,
				},
				{
					Name:       "err-file-sink",
					EventTypes: []Type{ErrorType},
					Format:     JSONSinkFormat,
					Path:       "./",
					FileName:   tmpErrFile.Name(),
				},
			},
		},
		AllEvents:   tmpAllFile,
		ErrorEvents: tmpErrFile,
	}
}
