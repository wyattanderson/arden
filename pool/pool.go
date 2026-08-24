package pool

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"math/rand/v2"
	"reflect"
	"sync"
	"time"

	"github.com/wyattanderson/arden"
)

// ProfileValidator compares the frozen initial profile with a replacement
// connection's profile. It must not include profile values in returned error
// text because profiles may contain directory data.
type ProfileValidator[P any] func(frozen, replacement P) error

// EndpointConfig contains the complete immutable construction inputs for one
// endpoint. When Initializer is non-nil, it is run for every connection; its
// first result is frozen and every replacement must match it before entering
// circulation.
type EndpointConfig[P any] struct {
	Endpoint        arden.Endpoint
	Dialer          *arden.Dialer
	Initializer     arden.Initializer[P]
	ValidateProfile ProfileValidator[P]
}

// Pool owns endpoint-specific sets of multiplexed LDAP connections.
type Pool[P any] struct {
	options Options
	ctx     context.Context
	cancel  context.CancelFunc

	mu           sync.Mutex
	closeMu      sync.Mutex
	closing      bool
	closed       bool
	waiters      int
	selectionSeq uint64
	changed      chan struct{}
	endpoints    map[arden.EndpointID]*endpointState[P]
	order        []*endpointState[P]
	wg           sync.WaitGroup
}

type endpointState[P any] struct {
	config EndpointConfig[P]

	identity arden.Identity
	profile  P
	policy   arden.ConnectionPolicy

	connections []*pooledConnection
	dialing     int
	waiters     int
	failures    uint64
	backoff     time.Duration
	nextDial    time.Time
	replacing   bool
}

type pooledConnection struct {
	conn     *arden.Conn
	created  time.Time
	lastIdle time.Time
	inFlight int
	leased   bool
	draining bool
	broken   bool
	retiring bool
}

// New validates and bootstraps one connection per endpoint. If any endpoint
// cannot establish its frozen setup profile, no partial pool is returned.
func New[P any](ctx context.Context, endpoints []EndpointConfig[P], options Options) (*Pool[P], error) {
	if ctx == nil {
		return nil, errors.New("pool: nil construction context")
	}
	if len(endpoints) == 0 {
		return nil, errors.New("pool: no endpoints configured")
	}
	normalized, err := options.normalized()
	if err != nil {
		return nil, err
	}
	poolCtx, cancel := context.WithCancel(context.Background())
	p := &Pool[P]{
		options:   normalized,
		ctx:       poolCtx,
		cancel:    cancel,
		changed:   make(chan struct{}),
		endpoints: make(map[arden.EndpointID]*endpointState[P], len(endpoints)),
	}
	for _, config := range endpoints {
		if err := config.Endpoint.Validate(); err != nil {
			cancel()
			p.closeConstructed()
			return nil, err
		}
		if _, duplicate := p.endpoints[config.Endpoint.ID]; duplicate {
			cancel()
			p.closeConstructed()
			return nil, errors.New("pool: duplicate endpoint ID")
		}
		if config.Dialer == nil {
			config.Dialer = new(arden.Dialer)
		}
		result, err := setupEndpoint(ctx, config)
		if err != nil {
			cancel()
			p.closeConstructed()
			return nil, &arden.RouteError{Endpoint: config.Endpoint.ID, Err: err}
		}
		now := time.Now()
		state := &endpointState[P]{
			config:   config,
			identity: result.Identity,
			profile:  result.Profile,
			policy:   result.Policy,
			connections: []*pooledConnection{{
				conn:     result.Conn,
				created:  now,
				lastIdle: now,
			}},
		}
		p.endpoints[config.Endpoint.ID] = state
		p.order = append(p.order, state)
	}
	for _, endpoint := range p.order {
		p.watchConnection(endpoint, endpoint.connections[0])
	}
	p.wg.Add(1)
	go p.maintain()
	return p, nil
}

func (p *Pool[P]) closeConstructed() {
	for _, endpoint := range p.order {
		for _, connection := range endpoint.connections {
			_ = connection.conn.Close()
		}
	}
}

// Do acquires bounded capacity using selection and starts exactly one
// operation. It never replays an operation after selecting a connection.
func (p *Pool[P]) Do(ctx context.Context, selection Selection, operation arden.AnyOperation) (arden.ResponseStream, error) {
	if operation == nil {
		return nil, errors.New("pool: nil operation")
	}
	if err := operation.Untyped().Validate(); err != nil {
		return nil, err
	}
	connection, err := p.acquire(ctx, selection, false)
	if err != nil {
		return nil, err
	}
	stream, err := connection.conn.Do(ctx, operation)
	if err != nil {
		p.releaseOperation(connection)
		if endpoint, exact := selection.EndpointID(); exact && routeFailure(err) {
			return nil, &arden.RouteError{Endpoint: endpoint, Err: err}
		}
		return nil, err
	}
	var routed arden.EndpointID
	if endpoint, exact := selection.EndpointID(); exact {
		routed = endpoint
	}
	return p.trackStream(stream, connection, nil, routed), nil
}

func (p *Pool[P]) acquire(ctx context.Context, selection Selection, lease bool) (*pooledConnection, error) {
	queuedAt := time.Now()
	if ctx == nil {
		return nil, errors.New("pool: nil acquisition context")
	}
	if err := selection.Validate(); err != nil {
		return nil, err
	}
	var exact *endpointState[P]
	if id, ok := selection.EndpointID(); ok {
		p.mu.Lock()
		exact = p.endpoints[id]
		p.mu.Unlock()
		if exact == nil {
			return nil, &arden.RouteError{Endpoint: id, Err: arden.ErrEndpointUnavailable}
		}
	}

	registeredWaiter := false
	for {
		p.mu.Lock()
		if p.closing {
			p.unregisterWaiterLocked(exact, &registeredWaiter)
			p.mu.Unlock()
			return nil, arden.ErrClosed
		}
		if connection := p.selectConnectionLocked(exact, lease); connection != nil {
			if lease {
				connection.leased = true
			} else {
				connection.inFlight++
			}
			p.unregisterWaiterLocked(exact, &registeredWaiter)
			stats := p.statsLocked()
			endpoint := connection.conn.Endpoint()
			p.mu.Unlock()
			poolDebug(ctx, p.loggerFor(endpoint.ID), "ldap pool capacity acquired",
				slog.String("endpoint_id", string(endpoint.ID)),
				slog.String("endpoint_address", endpoint.Address),
				slog.Uint64("connection_id", connection.conn.ID()),
				slog.Bool("lease", lease),
				slog.Duration("queue_duration", time.Since(queuedAt)),
				slog.Int("pool_size", stats.Connections),
				slog.Int("in_flight", stats.InFlight),
				slog.Int("waiters", stats.Waiters),
			)
			return connection, nil
		}

		endpoint, waitUntil := p.selectDialEndpointLocked(exact)
		if endpoint != nil {
			endpoint.dialing++
			p.signalLocked()
			p.mu.Unlock()
			connection, dialErr := p.dialEndpoint(ctx, endpoint)
			p.mu.Lock()
			endpoint.dialing--
			if dialErr == nil && !p.closing {
				endpoint.connections = append(endpoint.connections, connection)
				endpoint.backoff = 0
				endpoint.nextDial = time.Time{}
				p.signalLocked()
				p.mu.Unlock()
				p.watchConnection(endpoint, connection)
				continue
			}
			if dialErr == nil {
				connection.retiring = true
			}
			if dialErr != nil {
				p.recordDialFailureLocked(endpoint)
			}
			p.signalLocked()
			p.mu.Unlock()
			if dialErr == nil {
				_ = connection.conn.Close()
				return nil, arden.ErrClosed
			}
			p.startReplacement(endpoint)
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if exact != nil {
				return nil, &arden.RouteError{Endpoint: exact.config.Endpoint.ID, Err: dialErr}
			}
			continue
		}

		if !registeredWaiter {
			if p.waiters == p.options.MaxWaiters {
				p.mu.Unlock()
				return nil, &arden.LimitError{Limit: "pool waiters", Value: uint64(p.waiters + 1), Max: uint64(p.options.MaxWaiters)}
			}
			p.waiters++
			if exact != nil {
				exact.waiters++
			}
			registeredWaiter = true
		}
		changed := p.changed
		p.mu.Unlock()

		var timer <-chan time.Time
		var stop func() bool
		if !waitUntil.IsZero() {
			delay := max(time.Until(waitUntil), 0)
			t := time.NewTimer(delay)
			timer = t.C
			stop = t.Stop
		}
		select {
		case <-ctx.Done():
			if stop != nil {
				stop()
			}
			p.mu.Lock()
			p.unregisterWaiterLocked(exact, &registeredWaiter)
			p.mu.Unlock()
			return nil, ctx.Err()
		case <-p.ctx.Done():
			if stop != nil {
				stop()
			}
			p.mu.Lock()
			p.unregisterWaiterLocked(exact, &registeredWaiter)
			p.mu.Unlock()
			return nil, arden.ErrClosed
		case <-changed:
			if stop != nil {
				stop()
			}
		case <-timer:
		}
	}
}

func (p *Pool[P]) selectConnectionLocked(exact *endpointState[P], lease bool) *pooledConnection {
	var candidates []*pooledConnection
	endpoints := p.order
	if exact != nil {
		endpoints = []*endpointState[P]{exact}
	}
	minimum := p.options.MaxInFlightPerConnection + 1
	for _, endpoint := range endpoints {
		for _, connection := range endpoint.connections {
			if connection.broken || connection.draining || connection.leased {
				continue
			}
			if lease {
				if connection.inFlight != 0 {
					continue
				}
			} else if connection.inFlight >= p.options.MaxInFlightPerConnection {
				continue
			}
			if connection.inFlight < minimum {
				minimum = connection.inFlight
				candidates = candidates[:0]
			}
			if connection.inFlight == minimum {
				candidates = append(candidates, connection)
			}
		}
	}
	if len(candidates) == 0 {
		return nil
	}
	selected := candidates[p.selectionSeq%uint64(len(candidates))]
	p.selectionSeq++
	return selected
}

func (p *Pool[P]) selectDialEndpointLocked(exact *endpointState[P]) (*endpointState[P], time.Time) {
	now := time.Now()
	endpoints := p.order
	if exact != nil {
		endpoints = []*endpointState[P]{exact}
	}
	var candidates []*endpointState[P]
	minimum := p.options.MaxConnectionsPerEndpoint + 1
	var earliest time.Time
	for _, endpoint := range endpoints {
		live := endpoint.dialing
		for _, connection := range endpoint.connections {
			if !connection.broken && !connection.draining {
				live++
			}
		}
		if live >= p.options.MaxConnectionsPerEndpoint {
			continue
		}
		if endpoint.nextDial.After(now) {
			if earliest.IsZero() || endpoint.nextDial.Before(earliest) {
				earliest = endpoint.nextDial
			}
			continue
		}
		if live < minimum {
			minimum = live
			candidates = candidates[:0]
		}
		if live == minimum {
			candidates = append(candidates, endpoint)
		}
	}
	if len(candidates) == 0 {
		return nil, earliest
	}
	selected := candidates[p.selectionSeq%uint64(len(candidates))]
	p.selectionSeq++
	return selected, time.Time{}
}

func (p *Pool[P]) dialEndpoint(ctx context.Context, endpoint *endpointState[P]) (*pooledConnection, error) {
	result, err := setupEndpoint(ctx, endpoint.config)
	if err != nil {
		return nil, err
	}
	if result.Identity != endpoint.identity || result.Policy != endpoint.policy {
		_ = result.Conn.Close()
		return nil, &arden.SetupError{Endpoint: endpoint.config.Endpoint.ID, Stage: arden.SetupProfileMismatch, Err: arden.ErrProfileMismatch}
	}
	if endpoint.config.ValidateProfile != nil {
		if err := endpoint.config.ValidateProfile(endpoint.profile, result.Profile); err != nil {
			_ = result.Conn.Close()
			return nil, &arden.SetupError{Endpoint: endpoint.config.Endpoint.ID, Stage: arden.SetupProfileMismatch, Err: &arden.ProfileMismatchError{Err: err}}
		}
	} else if !reflect.DeepEqual(endpoint.profile, result.Profile) {
		_ = result.Conn.Close()
		return nil, &arden.SetupError{Endpoint: endpoint.config.Endpoint.ID, Stage: arden.SetupProfileMismatch, Err: arden.ErrProfileMismatch}
	}
	now := time.Now()
	return &pooledConnection{conn: result.Conn, created: now, lastIdle: now}, nil
}

func setupEndpoint[P any](ctx context.Context, config EndpointConfig[P]) (arden.SetupResult[P], error) {
	if config.Initializer != nil {
		return arden.Bootstrap(ctx, config.Dialer, config.Endpoint, config.Initializer)
	}
	conn, err := config.Dialer.Dial(ctx, config.Endpoint)
	if err != nil {
		return arden.SetupResult[P]{}, err
	}
	return arden.SetupResult[P]{
		Conn:     conn,
		Endpoint: config.Endpoint,
		Identity: conn.Identity(),
		Policy:   conn.Policy(),
	}, nil
}

func (p *Pool[P]) recordDialFailureLocked(endpoint *endpointState[P]) {
	endpoint.failures++
	if endpoint.backoff == 0 {
		endpoint.backoff = p.options.BackoffInitial
	} else {
		endpoint.backoff *= 2
		if endpoint.backoff > p.options.BackoffMaximum {
			endpoint.backoff = p.options.BackoffMaximum
		}
	}
	jitter := 1 + ((rand.Float64()*2)-1)*p.options.BackoffJitter
	endpoint.nextDial = time.Now().Add(time.Duration(float64(endpoint.backoff) * jitter))
}

func (p *Pool[P]) startReplacement(endpoint *endpointState[P]) {
	p.mu.Lock()
	if p.closing || endpoint.replacing || p.endpointHasLiveConnectionLocked(endpoint) {
		p.mu.Unlock()
		return
	}
	endpoint.replacing = true
	p.wg.Add(1)
	p.mu.Unlock()
	go p.replace(endpoint)
}

func (p *Pool[P]) replace(endpoint *endpointState[P]) {
	defer p.wg.Done()
	defer func() {
		p.mu.Lock()
		endpoint.replacing = false
		p.signalLocked()
		p.mu.Unlock()
	}()
	for {
		p.mu.Lock()
		if p.closing || p.endpointHasLiveConnectionLocked(endpoint) {
			p.mu.Unlock()
			return
		}
		wait := time.Until(endpoint.nextDial)
		if wait <= 0 {
			endpoint.dialing++
			p.signalLocked()
			p.mu.Unlock()
			connection, err := p.dialEndpoint(p.ctx, endpoint)
			p.mu.Lock()
			endpoint.dialing--
			if err == nil && !p.closing {
				endpoint.connections = append(endpoint.connections, connection)
				endpoint.backoff = 0
				endpoint.nextDial = time.Time{}
				p.signalLocked()
				p.mu.Unlock()
				p.watchConnection(endpoint, connection)
				return
			}
			if err == nil {
				connection.retiring = true
			} else {
				p.recordDialFailureLocked(endpoint)
			}
			p.signalLocked()
			p.mu.Unlock()
			if err == nil {
				_ = connection.conn.Close()
				return
			}
			continue
		}
		p.mu.Unlock()
		timer := time.NewTimer(wait)
		select {
		case <-timer.C:
		case <-p.ctx.Done():
			timer.Stop()
			return
		}
	}
}

func (p *Pool[P]) endpointHasLiveConnectionLocked(endpoint *endpointState[P]) bool {
	for _, connection := range endpoint.connections {
		if !connection.broken && !connection.draining {
			return true
		}
	}
	return false
}

func (p *Pool[P]) watchConnection(endpoint *endpointState[P], connection *pooledConnection) {
	p.wg.Go(func() {
		<-connection.conn.Done()
		p.mu.Lock()
		connection.broken = true
		connection.leased = false
		p.removeConnectionIfUnusedLocked(endpoint, connection)
		p.signalLocked()
		closing := p.closing || connection.retiring
		p.mu.Unlock()
		if !closing {
			p.startReplacement(endpoint)
		}
	})
}

func (p *Pool[P]) trackStream(stream arden.ResponseStream, connection *pooledConnection, lease *Lease[P], routed arden.EndpointID) arden.ResponseStream {
	tracked := &trackedStream{ResponseStream: stream}
	tracked.routed = routed
	tracked.release = func() {
		if lease == nil {
			p.releaseOperation(connection)
		} else {
			p.releaseLeaseOperation(lease)
		}
	}
	if lifecycle, ok := stream.(arden.ResponseLifecycle); ok {
		tracked.lifecycle = true
		go func() {
			<-lifecycle.Done()
			tracked.releaseOnce()
		}()
	}
	return tracked
}

type trackedStream struct {
	arden.ResponseStream
	once      sync.Once
	release   func()
	lifecycle bool
	routed    arden.EndpointID
}

func (s *trackedStream) Next(ctx context.Context) (arden.Response, error) {
	response, err := s.ResponseStream.Next(ctx)
	if err == io.EOF {
		s.releaseOnce()
	}
	if err != nil && s.routed != "" && routeFailure(err) {
		return response, &arden.RouteError{Endpoint: s.routed, Err: err}
	}
	return response, err
}

func (s *trackedStream) Close() error {
	err := s.ResponseStream.Close()
	if !s.lifecycle {
		s.releaseOnce()
	}
	return err
}

func (s *trackedStream) releaseOnce() { s.once.Do(s.release) }

func (p *Pool[P]) releaseOperation(connection *pooledConnection) {
	p.mu.Lock()
	if connection.inFlight > 0 {
		connection.inFlight--
	}
	if connection.inFlight == 0 {
		connection.lastIdle = time.Now()
		if connection.draining && !connection.leased {
			connection.retiring = true
			go func() { _ = connection.conn.Close() }()
		}
	}
	for _, endpoint := range p.order {
		p.removeConnectionIfUnusedLocked(endpoint, connection)
	}
	stats := p.statsLocked()
	p.signalLocked()
	p.mu.Unlock()
	endpoint := connection.conn.Endpoint()
	poolDebug(context.Background(), p.loggerFor(endpoint.ID), "ldap pool capacity released",
		slog.String("endpoint_id", string(endpoint.ID)),
		slog.String("endpoint_address", endpoint.Address),
		slog.Uint64("connection_id", connection.conn.ID()),
		slog.Int("pool_size", stats.Connections),
		slog.Int("in_flight", stats.InFlight),
		slog.Int("waiters", stats.Waiters),
	)
}

func (p *Pool[P]) unregisterWaiterLocked(endpoint *endpointState[P], registered *bool) {
	if !*registered {
		return
	}
	p.waiters--
	if endpoint != nil {
		endpoint.waiters--
	}
	*registered = false
}

func (p *Pool[P]) removeConnectionIfUnusedLocked(endpoint *endpointState[P], target *pooledConnection) {
	if target.inFlight != 0 || target.leased || (!target.broken && !target.retiring) {
		return
	}
	for i, connection := range endpoint.connections {
		if connection == target {
			endpoint.connections = append(endpoint.connections[:i], endpoint.connections[i+1:]...)
			return
		}
	}
}

func (p *Pool[P]) signalLocked() {
	close(p.changed)
	p.changed = make(chan struct{})
}

func (p *Pool[P]) loggerFor(endpoint arden.EndpointID) *slog.Logger {
	p.mu.Lock()
	defer p.mu.Unlock()
	state := p.endpoints[endpoint]
	if state == nil || state.config.Dialer == nil {
		return nil
	}
	return state.config.Dialer.Logger
}

func (p *Pool[P]) statsLocked() Stats {
	result := Stats{Waiters: p.waiters, Closing: p.closing}
	for _, endpoint := range p.order {
		result.Dialing += endpoint.dialing
		for _, connection := range endpoint.connections {
			if connection.broken {
				continue
			}
			result.Connections++
			result.InFlight += connection.inFlight
		}
	}
	return result
}

func poolDebug(ctx context.Context, logger *slog.Logger, message string, attrs ...slog.Attr) {
	if logger == nil {
		return
	}
	defer func() { _ = recover() }()
	if logger.Enabled(ctx, slog.LevelDebug) {
		logger.LogAttrs(ctx, slog.LevelDebug, message, attrs...)
	}
}

func routeFailure(err error) bool {
	return errors.Is(err, arden.ErrTransport) ||
		errors.Is(err, arden.ErrProtocol) ||
		errors.Is(err, arden.ErrNoticeOfDisconnection) ||
		errors.Is(err, arden.ErrClosed)
}

func (p *Pool[P]) maintain() {
	defer p.wg.Done()
	interval := p.options.IdleLifetime / 4
	if lifetimeInterval := p.options.MaximumLifetime / 4; lifetimeInterval < interval {
		interval = lifetimeInterval
	}
	if interval > time.Second {
		interval = time.Second
	}
	if interval < time.Millisecond {
		interval = time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case now := <-ticker.C:
			p.retireExpired(now)
		case <-p.ctx.Done():
			return
		}
	}
}

func (p *Pool[P]) retireExpired(now time.Time) {
	var closeConnections []*arden.Conn
	var replaceEndpoints []*endpointState[P]
	p.mu.Lock()
	if p.closing {
		p.mu.Unlock()
		return
	}
	for _, endpoint := range p.order {
		live := 0
		for _, connection := range endpoint.connections {
			if !connection.broken && !connection.draining {
				live++
			}
		}
		for _, connection := range endpoint.connections {
			if connection.broken || connection.draining || connection.leased {
				continue
			}
			expired := now.Sub(connection.created) >= p.options.MaximumLifetime
			idle := connection.inFlight == 0 && live > 1 && now.Sub(connection.lastIdle) >= p.options.IdleLifetime
			if !expired && !idle {
				continue
			}
			connection.draining = true
			live--
			if connection.inFlight == 0 {
				connection.retiring = true
				closeConnections = append(closeConnections, connection.conn)
			}
			if expired && live == 0 {
				replaceEndpoints = append(replaceEndpoints, endpoint)
			}
		}
	}
	p.signalLocked()
	p.mu.Unlock()
	for _, connection := range closeConnections {
		_ = connection.Close()
	}
	for _, endpoint := range replaceEndpoints {
		p.startReplacement(endpoint)
	}
}

// Close drains active work up to the configured shutdown timeout and then
// promptly closes every connection. It is idempotent.
func (p *Pool[P]) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), p.options.ShutdownTimeout)
	defer cancel()
	return p.CloseContext(ctx)
}

// CloseContext is the context-aware form of Close.
func (p *Pool[P]) CloseContext(ctx context.Context) error {
	if ctx == nil {
		return errors.New("pool: nil close context")
	}
	p.closeMu.Lock()
	defer p.closeMu.Unlock()
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	if !p.closing {
		p.closing = true
		p.cancel()
		p.signalLocked()
	}
	p.mu.Unlock()

	var drainErr error
	for {
		p.mu.Lock()
		active := 0
		changed := p.changed
		for _, endpoint := range p.order {
			for _, connection := range endpoint.connections {
				active += connection.inFlight
				if connection.leased {
					active++
				}
			}
		}
		p.mu.Unlock()
		if active == 0 {
			break
		}
		select {
		case <-changed:
		case <-ctx.Done():
			drainErr = ctx.Err()
			goto closeAll
		}
	}

closeAll:
	p.mu.Lock()
	var connections []*arden.Conn
	for _, endpoint := range p.order {
		for _, connection := range endpoint.connections {
			connection.retiring = true
			connections = append(connections, connection.conn)
		}
	}
	p.mu.Unlock()
	for _, connection := range connections {
		if err := connection.CloseContext(ctx); err != nil && drainErr == nil {
			drainErr = err
		}
	}
	p.wg.Wait()
	p.mu.Lock()
	p.closed = true
	p.signalLocked()
	p.mu.Unlock()
	return drainErr
}
