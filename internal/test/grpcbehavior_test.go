package test

import (
	"context"
	"fmt"
	"math"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/nettest"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/resolver"
	"google.golang.org/grpc/resolver/manual"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestManualResolver(t *testing.T) {
	ctx := context.Background()

	serverCount := 10

	srvWg := sync.WaitGroup{}
	srvWg.Add(serverCount)
	servers := make([]*serverTestInfo, 0, serverCount)
	for i := 0; i < serverCount; i++ {
		l1, err := nettest.NewLocalListener("tcp")
		require.NoError(t, err)
		srv := grpc.NewServer()
		lInfo := &serverTestInfo{srv: srv, address: l1.Addr().String(), id: i + 1}
		tl := &testListener{Listener: l1, info: lInfo, t: t}
		servers = append(servers, lInfo)
		go func(i int) {
			defer srvWg.Done()
			servers[i].srv.Serve(tl)
		}(i)
	}

	scheme := strconv.FormatInt(time.Now().UnixNano(), 36)
	res := manual.NewBuilderWithScheme(scheme)
	res.InitialState(getState([]string{servers[0].address}))

	defaultTimeout := (time.Second + time.Nanosecond).String()
	defServiceConfig := fmt.Sprintf(`
	  {
		"loadBalancingConfig": [ { "round_robin": {} } ],
		"methodConfig": [
		  {
			"name": [],
			"timeout": %q,
			"waitForReady": true
		  }
		]
	  }
	  `, defaultTimeout)
	dialOpts := []grpc.DialOption{
		grpc.WithResolvers(res),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(math.MaxInt32)),
		grpc.WithDefaultCallOptions(grpc.MaxCallSendMsgSize(math.MaxInt32)),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultServiceConfig(defServiceConfig),
		// Don't have the resolver reach out for a service config from the
		// resolver, use the one specified as default
		grpc.WithDisableServiceConfig(),
		grpc.WithConnectParams(grpc.ConnectParams{
			Backoff: backoff.Config{
				BaseDelay:  time.Second,
				Multiplier: 1.2,
				Jitter:     0.2,
				MaxDelay:   3 * time.Second,
			},
		}),
	}
	cc, err := grpc.Dial(
		fmt.Sprintf("%s:///%s", res.Scheme(), servers[0].address),
		dialOpts...,
	)
	require.NoError(t, err)
	t.Log("initial state setup")

	state := cc.GetState()
	t.Logf("First state is %v", state)

	for state != connectivity.Ready && state != connectivity.TransientFailure {
		cc.WaitForStateChange(ctx, state)
		state = cc.GetState()
	}
	require.Equal(t, connectivity.Ready, state)

	assert.Equal(t, 1, servers[0].acceptCount)

	// Send frequent requests. Even if they are unimplemented errors
	req, err := structpb.NewStruct(map[string]interface{}{"something": "foo"})
	require.NoError(t, err)
	go func() {
		tick := time.NewTicker(time.Second)
		for {
			select {
			case <-tick.C:
				cc.Invoke(ctx, "/github.com.hashicorp.testService/TestMethod", req, req)
			}
		}
	}()

	// Log all future state changes
	stateChangeCtx, cancel := context.WithCancel(ctx)
	go func() {
		for cc.WaitForStateChange(stateChangeCtx, state) {
			state = cc.GetState()
			t.Logf("New state set to %v", state)
		}
		t.Log("No longer tracking state changes")
	}()

	{
		t.Log("State is ready, now connecting another address")
		res.UpdateState(getState([]string{servers[0].address, servers[1].address}))
		t.Log("Added another address")
		time.Sleep(1 * time.Second)
	}

	{
		t.Log("now connecting bad address")
		res.UpdateState(getState([]string{servers[0].address, servers[1].address, "bad_address"}))
		t.Log("Added a bad address")
		time.Sleep(2 * time.Second)
	}

	{
		t.Log("now disconnecting original address")
		res.UpdateState(getState([]string{servers[1].address, "bad_address"}))
		t.Log("disconnected original address")
		time.Sleep(2 * time.Second)
	}

	{
		t.Log("adding 3rd address")
		res.UpdateState(getState([]string{servers[1].address, "bad_address", servers[2].address}))
		t.Log("added 3rd address")
		time.Sleep(2 * time.Second)
	}

	{
		t.Log("leaving just the bad address")
		res.UpdateState(getState([]string{"bad_address"}))
		t.Log("left just the bad address")
		time.Sleep(2 * time.Second)
	}

	{
		t.Log("set just the second address")
		res.UpdateState(getState([]string{servers[1].address}))
		t.Log("set just the second address")
		time.Sleep(2 * time.Second)
		t.Log("swap to just the 3rd address")
		res.UpdateState(getState([]string{servers[2].address}))
		t.Log("swapped to 3rd address")
		time.Sleep(2 * time.Second)
	}

	{
		t.Log("closing 2nd address's server")
		servers[1].srv.GracefulStop()
		t.Log("closed 2nd address's server")
		time.Sleep(2 * time.Second)
	}

	{
		t.Log("adding 4th-final addresses")
		addrs := []string{servers[1].address, "bad_address", servers[2].address}
		for _, s := range servers[3:] {
			addrs = append(addrs, s.address)
		}
		res.UpdateState(getState(addrs))
		t.Log("added 4th-final addresses")
		time.Sleep(2 * time.Second)
	}

	time.Sleep(10 * time.Second)

	t.Log("Done, shutting down")
	cancel()
	for _, s := range servers {
		s.srv.GracefulStop()
	}
	// Wait for all servers to be created
	srvWg.Wait()
}

func getState(addrs []string) resolver.State {
	var rAddrs []resolver.Address
	for _, a := range addrs {
		rAddrs = append(rAddrs, resolver.Address{Addr: a})
	}
	return resolver.State{Addresses: rAddrs}
}

type serverTestInfo struct {
	srv             *grpc.Server
	acceptCount     int
	connClosedCount int
	address         string
	id              int
}

type testListener struct {
	net.Listener
	t    *testing.T
	info *serverTestInfo
}

func (l *testListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	l.t.Logf("Accept returned for %d", l.info.id)
	l.info.acceptCount++
	return &testConn{Conn: c, t: l.t, info: l.info}, nil
}

type testConn struct {
	net.Conn
	t    *testing.T
	info *serverTestInfo
}

func (c *testConn) Close() error {
	c.t.Logf("Close called for %d", c.info.id)
	c.info.connClosedCount++
	return c.Conn.Close()
}
