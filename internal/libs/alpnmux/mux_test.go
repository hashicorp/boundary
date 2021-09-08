package alpnmux

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/observability/event"
	"github.com/hashicorp/go-hclog"
	"go.uber.org/atomic"
)

func TestListenCloseErrMsg(t *testing.T) {
	listener := getListener(t)
	listener.Close()
	_, err := listener.Accept()
	if !strings.Contains(err.Error(), "use of closed network connection") {
		t.Fatal(err)
	}
}

func TestRegistrationErrors(t *testing.T) {
	listener := getListener(t)
	defer listener.Close()
	mux := New(listener)
	p1config := getTestTLS(t, []string{"p1"})
	if _, err := mux.RegisterProto("p1", nil); err.Error() != "nil tls config given" {
		t.Fatal(err)
	}
	l, err := mux.RegisterProto("p1", p1config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mux.RegisterProto("p1", p1config); err.Error() != `proto "p1" already registered` {
		t.Fatal(err)
	}
	l.Close()
	// Unregister is not sync, so need to wait for it to actually be removed
	var unregistered bool
	for i := 0; i < 5; i++ {
		_, ok := mux.muxMap.Load("p1")
		if !ok {
			unregistered = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !unregistered {
		t.Fatal("failed to unregister proto")
	}
	l, err = mux.RegisterProto("p1", p1config)
	if err != nil {
		t.Fatal(err)
	}
	l.Close()
	l, err = mux.RegisterProto(NoProto, nil)
	if err != nil {
		t.Fatal(err)
	}
	l.Close()
}

func TestListening(t *testing.T) {
	event.TestEnableEventing(t, true)
	testConfig := event.DefaultEventerConfig()
	testLock := &sync.Mutex{}
	testLogger := hclog.New(&hclog.LoggerOptions{
		Mutex: testLock,
	})
	err := event.InitSysEventer(testLogger, testLock, "TestListening", event.WithEventerConfig(testConfig))
	if err != nil {
		t.Fatal(err)
	}
	listener := getListener(t)

	mux := New(listener)
	defer mux.Close()

	emptyconns := atomic.NewUint32(0)
	noneconns := atomic.NewUint32(0)
	l1conns := atomic.NewUint32(0)
	l2conns := atomic.NewUint32(0)
	l3conns := atomic.NewUint32(0)
	defconns := atomic.NewUint32(0)
	clientCountTracker := atomic.NewUint32(0)

	baseconfig := getTestTLS(t, nil)
	noneconfig := baseconfig.Clone()
	p1config := baseconfig.Clone()
	p1config.NextProtos = []string{"p1"}
	p2p3config := getTestTLS(t, []string{"p2", "p3"})
	p3config := p2p3config.Clone()
	p3config.NextProtos = []string{"p3"}
	defconfig := baseconfig.Clone()
	defconfig.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		ret := baseconfig.Clone()
		ret.NextProtos = []string{fmt.Sprintf("%d", clientCountTracker.Load())}
		log.Printf("returning def config with next protos = %v\n", ret.NextProtos)
		clientCountTracker.Inc()
		return ret, nil
	}

	lempty, err := mux.RegisterProto("", noneconfig)
	if err != nil {
		t.Fatal(err)
	}
	l1, err := mux.RegisterProto("p1", p1config)
	if err != nil {
		t.Fatal(err)
	}
	l2, err := mux.RegisterProto("p2", p2p3config)
	if err != nil {
		t.Fatal(err)
	}
	l3, err := mux.RegisterProto("p3", p2p3config)
	if err != nil {
		t.Fatal(err)
	}
	lnone, err := mux.RegisterProto(NoProto, nil)
	if err != nil {
		t.Fatal(err)
	}
	ldef, err := mux.RegisterProto(DefaultProto, defconfig)
	if err != nil {
		t.Fatal(err)
	}

	addr := listener.Addr().String()
	wg := new(sync.WaitGroup)
	wg.Add(6)
	connWatchFunc := func(l net.Listener, connCounter *atomic.Uint32, tlsConf *tls.Config, numConns int) {
		defer wg.Done()
		tlsToUse := tlsConf
		go func() {
			for i := 0; i < numConns; i++ {
				var err error
				var conn net.Conn
				switch tlsToUse {
				case nil:
					conn, err = net.Dial("tcp4", addr)
					if err != nil {
						t.Fatal(err)
					}
					// We need to send some data here because we won't have any
					// from just the TLS handshake
					log.Println("defconn")
					n, err := conn.Write([]byte("GET "))
					if err != nil {
						t.Fatal(err)
					}
					if n != 4 {
						t.Fatal(n)
					}
					log.Println("defconn done")

				default:
					if connCounter == defconns {
						tlsToUse = baseconfig.Clone()
						log.Println("FOUND CURR")
						tlsToUse.NextProtos = []string{fmt.Sprintf("%d", i)}
					}
					log.Println(fmt.Sprintf("dialing on %d, counter = %d, protos = %v", numConns, i, tlsToUse.NextProtos))
					conn, err = tls.Dial("tcp4", addr, tlsToUse)
					if err != nil {
						t.Fatal(err)
					}
					log.Println(fmt.Sprintf("dialing done on %d, counter = %d, protos = %v", numConns, i, tlsToUse.NextProtos))
				}
				conn.Close()
			}
		}()
		for i := 0; i < numConns; i++ {
			log.Println(fmt.Sprintf("accepting on %d, counter = %d", numConns, connCounter.Load()))
			conn, err := l.Accept()
			if err == nil && conn != nil {
				conn.Close()
			} else {
				t.Fatal(err)
			}
			log.Println(fmt.Sprintf("done accepting on %d, counter = %d", numConns, connCounter.Load()))
			connCounter.Inc()
		}
		return
	}
	go connWatchFunc(lempty, emptyconns, noneconfig, 4)
	go connWatchFunc(l1, l1conns, p1config, 5)
	go connWatchFunc(l2, l2conns, p2p3config, 6)
	go connWatchFunc(l3, l3conns, p3config, 7)
	go connWatchFunc(lnone, noneconns, nil, 8)
	go connWatchFunc(ldef, defconns, defconfig, 9)
	wg.Wait()

	if emptyconns.Load() != 4 || l1conns.Load() != 5 || l2conns.Load() != 6 || l3conns.Load() != 7 || noneconns.Load() != 8 || defconns.Load() != 9 {
		t.Fatal("wrong number of conns")
	}
}
