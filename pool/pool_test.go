package pool_test

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wyattanderson/arden"
	"github.com/wyattanderson/arden/ber"
	ardenpool "github.com/wyattanderson/arden/pool"
)

var (
	requestID  = ber.Identifier{Class: ber.ClassApplication, Constructed: true, Number: 6}
	continueID = ber.Identifier{Class: ber.ClassApplication, Constructed: true, Number: 4}
	responseID = ber.Identifier{Class: ber.ClassApplication, Constructed: true, Number: 7}
	unbindID   = ber.Identifier{Class: ber.ClassApplication, Number: 2}
)

type testProtocol struct{}

type testResponse struct{}

func (*testResponse) UnmarshalBER(*ber.Reader) error { return nil }

func (testProtocol) ProtocolIdentifier() ber.Identifier { return requestID }
func (testProtocol) BERPacket() ber.Packet {
	return ber.Constructed(requestID).BERPacket()
}

func testOperation(t testing.TB) arden.Operation[testResponse] {
	t.Helper()
	pattern, err := arden.NewResponsePattern[testResponse](arden.ResponseSpec{Complete: []ber.Identifier{responseID}})
	assert.NoError(t, err)
	return arden.Operation[testResponse]{
		Protocol:     testProtocol{},
		Responses:    pattern,
		Cancellation: arden.CancelDrain,
		Metadata:     arden.OperationMetadata{Label: "test.modify"},
	}
}

func streamingOperation(t testing.TB) arden.Operation[testResponse] {
	t.Helper()
	pattern, err := arden.NewResponsePattern[testResponse](arden.ResponseSpec{
		Continue: []ber.Identifier{continueID}, Complete: []ber.Identifier{responseID},
	})
	require.NoError(t, err)
	return arden.Operation[testResponse]{
		Protocol:     testProtocol{},
		Responses:    pattern,
		Cancellation: arden.CancelDrain,
		Metadata:     arden.OperationMetadata{Label: "test.streaming"},
	}
}

type initializer struct{ profile string }

func (i initializer) Initialize(context.Context, arden.InitializationSession) (string, arden.ConnectionPolicy, error) {
	return i.profile, arden.ConnectionPolicy{Cancellation: arden.CancellationConservative}, nil
}

type changingInitializer struct{ profile *atomic.Value }

func (i changingInitializer) Initialize(context.Context, arden.InitializationSession) (string, arden.ConnectionPolicy, error) {
	return i.profile.Load().(string), arden.ConnectionPolicy{Cancellation: arden.CancellationConservative}, nil
}

type requestAction uint8

const (
	respond requestAction = iota + 1
	breakConnection
)

type serverRequest struct {
	connection int
	action     chan requestAction
}

type testServer struct {
	listener  net.Listener
	requests  chan serverRequest
	accepted  atomic.Int64
	automatic bool
	responses int

	mu    sync.Mutex
	conns map[net.Conn]struct{}
}

func newTestServer(t *testing.T) *testServer {
	t.Helper()
	return newPoolTestServer(t, false)
}

func newPoolTestServer(t testing.TB, automatic bool) *testServer {
	t.Helper()
	listener, err := new(net.ListenConfig).Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	server := &testServer{listener: listener, requests: make(chan serverRequest, 32), conns: make(map[net.Conn]struct{}), automatic: automatic, responses: 1}
	go server.accept()
	t.Cleanup(func() { server.close() })
	return server
}

func (s *testServer) endpoint(id arden.EndpointID) arden.Endpoint {
	return arden.Endpoint{ID: id, Address: s.listener.Addr().String(), Transport: arden.TransportPlaintext}
}

func (s *testServer) accept() {
	for {
		connection, err := s.listener.Accept()
		if err != nil {
			return
		}
		ordinal := int(s.accepted.Add(1) - 1)
		s.mu.Lock()
		s.conns[connection] = struct{}{}
		s.mu.Unlock()
		go s.serve(connection, ordinal)
	}
}

func (s *testServer) serve(connection net.Conn, ordinal int) {
	defer func() {
		s.mu.Lock()
		delete(s.conns, connection)
		s.mu.Unlock()
		_ = connection.Close()
	}()
	framer, err := ber.NewFramer(connection, ber.DefaultLimits())
	if err != nil {
		return
	}
	var writeMu sync.Mutex
	for {
		message, err := framer.Next()
		if err != nil {
			return
		}
		request, err := arden.ParseResponse(message, ber.DefaultLimits())
		if err != nil {
			return
		}
		if request.ProtocolID == unbindID {
			return
		}
		event := serverRequest{connection: ordinal, action: make(chan requestAction, 1)}
		if s.automatic {
			event.action <- respond
		} else {
			s.requests <- event
		}
		go func(messageID arden.MessageID) {
			if <-event.action == breakConnection {
				_ = connection.Close()
				return
			}
			writeMu.Lock()
			for i := 0; i < s.responses; i++ {
				identifier := continueID
				if i == s.responses-1 {
					identifier = responseID
				}
				response := ber.Sequence().
					Add(ber.Integer(messageID)).
					Add(ber.Constructed(identifier)).
					BERPacket().Encode()
				_, _ = connection.Write(response)
			}
			writeMu.Unlock()
		}(request.MessageID)
	}
}

func (s *testServer) close() {
	_ = s.listener.Close()
	s.mu.Lock()
	for connection := range s.conns {
		_ = connection.Close()
	}
	s.mu.Unlock()
}

func poolOptions() ardenpool.Options {
	options := ardenpool.DefaultOptions()
	options.MaxConnectionsPerEndpoint = 2
	options.MaxInFlightPerConnection = 2
	options.MaxWaiters = 4
	options.IdleLifetime = time.Minute
	options.MaximumLifetime = time.Hour
	options.ShutdownTimeout = time.Second
	options.BackoffInitial = 5 * time.Millisecond
	options.BackoffMaximum = 20 * time.Millisecond
	return options
}

func openPool(t *testing.T, options ardenpool.Options, servers ...*testServer) *ardenpool.Pool[string] {
	t.Helper()
	configs := make([]ardenpool.EndpointConfig[string], 0, len(servers))
	for i, server := range servers {
		configs = append(configs, ardenpool.EndpointConfig[string]{
			Endpoint:    server.endpoint(arden.EndpointID(string(rune('a' + i)))),
			Dialer:      new(arden.Dialer),
			Initializer: initializer{profile: "profile"},
		})
	}
	pool, err := ardenpool.New(context.Background(), configs, options)
	require.NoError(t, err)
	t.Cleanup(func() { _ = pool.Close() })
	return pool
}

func nextRequest(t *testing.T, server *testServer) serverRequest {
	t.Helper()
	select {
	case request := <-server.requests:
		return request
	case <-time.After(time.Second):
		require.Fail(t, "timed out waiting for LDAP request")
		return serverRequest{}
	}
}

func completeStream(t *testing.T, request serverRequest, stream arden.ResponseStream) {
	t.Helper()
	request.action <- respond
	response, err := stream.Next(context.Background())
	require.NoError(t, err)
	require.Equal(t, responseID, response.ProtocolID)
	_, err = stream.Next(context.Background())
	require.ErrorIs(t, err, io.EOF)
}

func TestPoolSelectsLeastLoadedConnection(t *testing.T) {
	server := newTestServer(t)
	pool := openPool(t, poolOptions(), server)
	operation := testOperation(t)

	streams := make([]arden.ResponseStream, 0, 4)
	requests := make([]serverRequest, 0, 4)
	for range 4 {
		stream, err := pool.Do(context.Background(), ardenpool.Any(), operation)
		require.NoError(t, err)
		streams = append(streams, stream)
		requests = append(requests, nextRequest(t, server))
	}
	assert.Equal(t, []int{0, 0, 1, 1}, []int{requests[0].connection, requests[1].connection, requests[2].connection, requests[3].connection})
	for i := range streams {
		completeStream(t, requests[i], streams[i])
	}
	eventually(t, func() bool { return pool.Stats().InFlight == 0 })
}

func TestPoolAllowsEndpointsWithoutHigherLayerInitializer(t *testing.T) {
	server := newTestServer(t)
	pool, err := ardenpool.New(context.Background(), []ardenpool.EndpointConfig[struct{}]{
		{Endpoint: server.endpoint("plain"), Dialer: new(arden.Dialer)},
	}, poolOptions())
	require.NoError(t, err)
	t.Cleanup(func() { _ = pool.Close() })
	stream, err := pool.Do(context.Background(), ardenpool.Any(), testOperation(t))
	require.NoError(t, err)
	completeStream(t, nextRequest(t, server), stream)
}

func TestExactEndpointNeverReroutesAndReplacementKeepsIdentity(t *testing.T) {
	first := newTestServer(t)
	second := newTestServer(t)
	options := poolOptions()
	options.MaxConnectionsPerEndpoint = 1
	pool := openPool(t, options, first, second)
	selection, err := ardenpool.Endpoint("a")
	require.NoError(t, err)
	stream, err := pool.Do(context.Background(), selection, testOperation(t))
	require.NoError(t, err)
	request := nextRequest(t, first)
	request.action <- breakConnection
	_, err = stream.Next(context.Background())
	require.ErrorIs(t, err, arden.ErrEndpointUnavailable)
	require.ErrorIs(t, err, arden.ErrAmbiguousOutcome)
	select {
	case request := <-second.requests:
		assert.Fail(t, "pinned request rerouted", "connection %d", request.connection)
	case <-time.After(30 * time.Millisecond):
	}
	eventually(t, func() bool { return first.accepted.Load() >= 2 })

	replacement, err := pool.Do(context.Background(), selection, testOperation(t))
	require.NoError(t, err)
	replacementRequest := nextRequest(t, first)
	assert.Equal(t, 1, replacementRequest.connection)
	completeStream(t, replacementRequest, replacement)
}

func TestAnyDistributesAcrossEligibleEndpoints(t *testing.T) {
	first := newTestServer(t)
	second := newTestServer(t)
	options := poolOptions()
	options.MaxConnectionsPerEndpoint = 1
	options.MaxInFlightPerConnection = 1
	pool := openPool(t, options, first, second)
	firstStream, err := pool.Do(context.Background(), ardenpool.Any(), testOperation(t))
	require.NoError(t, err)
	firstRequest := nextRequest(t, first)
	secondStream, err := pool.Do(context.Background(), ardenpool.Any(), testOperation(t))
	require.NoError(t, err)
	secondRequest := nextRequest(t, second)
	completeStream(t, firstRequest, firstStream)
	completeStream(t, secondRequest, secondStream)
}

func TestPoolBoundsWaitersAndHonorsCancellation(t *testing.T) {
	server := newTestServer(t)
	options := poolOptions()
	options.MaxConnectionsPerEndpoint = 1
	options.MaxInFlightPerConnection = 1
	options.MaxWaiters = 1
	pool := openPool(t, options, server)
	first, err := pool.Do(context.Background(), ardenpool.Any(), testOperation(t))
	require.NoError(t, err)
	firstRequest := nextRequest(t, server)

	waitCtx, cancel := context.WithCancel(context.Background())
	waitErr := make(chan error, 1)
	go func() {
		_, err := pool.Do(waitCtx, ardenpool.Any(), testOperation(t))
		waitErr <- err
	}()
	eventually(t, func() bool { return pool.Stats().Waiters == 1 })
	_, err = pool.Do(context.Background(), ardenpool.Any(), testOperation(t))
	require.ErrorIs(t, err, arden.ErrResourceLimit)
	cancel()
	require.ErrorIs(t, <-waitErr, context.Canceled)
	completeStream(t, firstRequest, first)
}

func TestLeaseIsExclusiveUntilActiveOperationsFinish(t *testing.T) {
	server := newTestServer(t)
	options := poolOptions()
	options.MaxConnectionsPerEndpoint = 1
	options.MaxInFlightPerConnection = 1
	pool := openPool(t, options, server)
	lease, err := pool.Lease(context.Background(), ardenpool.Any())
	require.NoError(t, err)
	stream, err := lease.Do(context.Background(), testOperation(t))
	require.NoError(t, err)
	request := nextRequest(t, server)
	require.NoError(t, lease.Close())

	waitCtx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	_, err = pool.Do(waitCtx, ardenpool.Any(), testOperation(t))
	require.ErrorIs(t, err, context.DeadlineExceeded)
	completeStream(t, request, stream)
	eventually(t, func() bool { return pool.Stats().InFlight == 0 })

	next, err := pool.Do(context.Background(), ardenpool.Any(), testOperation(t))
	require.NoError(t, err)
	nextRequest := nextRequest(t, server)
	assert.Equal(t, request.connection, nextRequest.connection)
	completeStream(t, nextRequest, next)
}

func TestBrokenLeaseNeverMovesToAnotherConnectionOrEndpoint(t *testing.T) {
	first := newTestServer(t)
	second := newTestServer(t)
	options := poolOptions()
	options.MaxConnectionsPerEndpoint = 1
	leasePool := openPool(t, options, first, second)
	lease, err := leasePool.Lease(context.Background(), ardenpool.Any())
	require.NoError(t, err)
	t.Cleanup(func() { _ = lease.Close() })
	require.Equal(t, arden.EndpointID("a"), lease.Endpoint().ID)
	stream, err := lease.Do(context.Background(), testOperation(t))
	require.NoError(t, err)
	request := nextRequest(t, first)
	request.action <- breakConnection
	_, err = stream.Next(context.Background())
	require.ErrorIs(t, err, arden.ErrEndpointUnavailable)
	require.ErrorIs(t, err, arden.ErrAmbiguousOutcome)
	eventually(t, func() bool {
		select {
		case <-lease.Done():
			return true
		default:
			return false
		}
	})
	_, err = lease.Do(context.Background(), testOperation(t))
	require.ErrorIs(t, err, arden.ErrEndpointUnavailable)
	select {
	case request := <-second.requests:
		assert.Fail(t, "broken lease moved to endpoint b", "connection %d", request.connection)
	case <-time.After(30 * time.Millisecond):
	}
}

func TestPoolCloseGracefullyDrainsActiveOperation(t *testing.T) {
	server := newTestServer(t)
	pool := openPool(t, poolOptions(), server)
	stream, err := pool.Do(context.Background(), ardenpool.Any(), testOperation(t))
	require.NoError(t, err)
	request := nextRequest(t, server)
	closed := make(chan error, 1)
	go func() { closed <- pool.Close() }()
	select {
	case err := <-closed:
		assert.Fail(t, "pool closed before active operation completed", "%v", err)
	case <-time.After(30 * time.Millisecond):
	}
	completeStream(t, request, stream)
	require.NoError(t, <-closed)
	_, err = pool.Do(context.Background(), ardenpool.Any(), testOperation(t))
	require.ErrorIs(t, err, arden.ErrClosed)
}

func TestReplacementRejectsChangedFrozenProfile(t *testing.T) {
	server := newTestServer(t)
	var profile atomic.Value
	profile.Store("initial")
	options := poolOptions()
	options.MaxConnectionsPerEndpoint = 1
	config := ardenpool.EndpointConfig[string]{
		Endpoint: server.endpoint("profiled"), Dialer: new(arden.Dialer), Initializer: changingInitializer{profile: &profile},
	}
	pool, err := ardenpool.New(context.Background(), []ardenpool.EndpointConfig[string]{config}, options)
	require.NoError(t, err)
	t.Cleanup(func() { _ = pool.Close() })
	profile.Store("changed")
	selection, _ := ardenpool.Endpoint("profiled")
	stream, err := pool.Do(context.Background(), selection, testOperation(t))
	require.NoError(t, err)
	request := nextRequest(t, server)
	request.action <- breakConnection
	_, err = stream.Next(context.Background())
	require.ErrorIs(t, err, arden.ErrEndpointUnavailable)
	eventually(t, func() bool {
		stats := pool.Stats()
		return len(stats.Endpoints) == 1 && stats.Endpoints[0].Connections == 0 && stats.Endpoints[0].Failures > 0
	})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	_, err = pool.Do(ctx, selection, testOperation(t))
	require.Error(t, err)
	assert.Condition(t, func() bool {
		return errors.Is(err, context.DeadlineExceeded) || errors.Is(err, arden.ErrEndpointUnavailable)
	})
}

func TestMaximumLifetimeDrainsAndReplacesConnection(t *testing.T) {
	server := newTestServer(t)
	options := poolOptions()
	options.MaxConnectionsPerEndpoint = 1
	options.MaximumLifetime = 10 * time.Millisecond
	pool := openPool(t, options, server)
	initial := pool.ConnectionStats()
	require.Len(t, initial, 1)
	eventually(t, func() bool {
		connections := pool.ConnectionStats()
		return server.accepted.Load() >= 2 && len(connections) == 1 && connections[0].Connection != initial[0].Connection
	})
}

func eventually(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			require.Fail(t, "condition was not satisfied")
		}
		time.Sleep(time.Millisecond)
	}
}

func BenchmarkPoolMultiplexedOperations(b *testing.B) {
	benchmarkPoolWorkload(b, "unary", 1, testOperation)
	benchmarkPoolWorkload(b, "streaming", 4, streamingOperation)
}

func benchmarkPoolWorkload(b *testing.B, name string, responses int, operation func(testing.TB) arden.Operation[testResponse]) {
	b.Run(name, func(b *testing.B) {
		for _, inFlight := range []int{1, 4, 8, 16} {
			b.Run("in_flight_"+strconv.Itoa(inFlight), func(b *testing.B) {
				server := newPoolTestServer(b, true)
				server.responses = responses
				options := poolOptions()
				options.MaxInFlightPerConnection = inFlight
				options.MaxWaiters = 1024
				pool, err := ardenpool.New(context.Background(), []ardenpool.EndpointConfig[string]{
					{Endpoint: server.endpoint("benchmark"), Dialer: new(arden.Dialer), Initializer: initializer{profile: "profile"}},
				}, options)
				if err != nil {
					b.Fatal(err)
				}
				b.Cleanup(func() { _ = pool.Close() })
				op := operation(b)
				b.ResetTimer()
				b.RunParallel(func(pb *testing.PB) {
					for pb.Next() {
						stream, err := pool.Do(context.Background(), ardenpool.Any(), op)
						if err != nil {
							b.Error(err)
							return
						}
						for {
							if _, err := stream.Next(context.Background()); err != nil {
								if errors.Is(err, io.EOF) {
									break
								}
								b.Error(err)
								return
							}
						}
					}
				})
			})
		}
	})
}
