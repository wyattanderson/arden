package pool

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/wyattanderson/arden"
)

// Lease retains exclusive use of one connection. Operations issued through a
// lease may still multiplex up to MaxInFlightPerConnection on that connection.
// A broken lease never migrates to a replacement connection.
type Lease[P any] struct {
	pool       *Pool[P]
	connection *pooledConnection
	once       sync.Once
	closed     bool
	inFlight   int
}

// Lease acquires an exclusive connection within the selected endpoint.
// SelectionAny chooses the endpoint only once, at acquisition time.
func (p *Pool[P]) Lease(ctx context.Context, selection Selection) (*Lease[P], error) {
	connection, err := p.acquire(ctx, selection, true)
	if err != nil {
		return nil, err
	}
	return &Lease[P]{pool: p, connection: connection}, nil
}

// Endpoint returns the exact endpoint to which the lease is bound.
func (l *Lease[P]) Endpoint() arden.Endpoint { return l.connection.conn.Endpoint() }

// ConnectionID returns the process-scoped ID of the leased connection.
func (l *Lease[P]) ConnectionID() uint64 { return l.connection.conn.ID() }

// Done is closed if the retained connection breaks or is shut down.
func (l *Lease[P]) Done() <-chan struct{} { return l.connection.conn.Done() }

// Do starts one operation on the retained connection without rerouting.
func (l *Lease[P]) Do(ctx context.Context, operation arden.Operation) (arden.ResponseStream, error) {
	if ctx == nil {
		return nil, errors.New("pool: nil lease operation context")
	}
	if err := operation.Validate(); err != nil {
		return nil, err
	}
	if err := l.acquireOperation(ctx); err != nil {
		return nil, err
	}
	stream, err := l.connection.conn.Do(ctx, operation)
	if err != nil {
		l.pool.releaseLeaseOperation(l)
		if routeFailure(err) {
			return nil, &arden.RouteError{Endpoint: l.Endpoint().ID, Err: err}
		}
		return nil, err
	}
	return l.pool.trackStream(stream, l.connection, l, l.Endpoint().ID), nil
}

func (l *Lease[P]) acquireOperation(ctx context.Context) error {
	p := l.pool
	registeredWaiter := false
	for {
		p.mu.Lock()
		if l.closed || p.closing {
			p.unregisterWaiterLocked(nil, &registeredWaiter)
			p.mu.Unlock()
			return arden.ErrClosed
		}
		if l.connection.broken || l.connection.conn.Err() != nil {
			p.unregisterWaiterLocked(nil, &registeredWaiter)
			p.mu.Unlock()
			return &arden.RouteError{Endpoint: l.Endpoint().ID, Err: arden.ErrEndpointUnavailable}
		}
		if l.inFlight < p.options.MaxInFlightPerConnection {
			l.inFlight++
			l.connection.inFlight++
			p.unregisterWaiterLocked(nil, &registeredWaiter)
			p.signalLocked()
			p.mu.Unlock()
			return nil
		}
		if !registeredWaiter {
			if p.waiters == p.options.MaxWaiters {
				p.mu.Unlock()
				return &arden.LimitError{Limit: "pool waiters", Value: uint64(p.waiters + 1), Max: uint64(p.options.MaxWaiters)}
			}
			p.waiters++
			registeredWaiter = true
		}
		changed := p.changed
		p.mu.Unlock()
		select {
		case <-ctx.Done():
			p.mu.Lock()
			p.unregisterWaiterLocked(nil, &registeredWaiter)
			p.mu.Unlock()
			return ctx.Err()
		case <-p.ctx.Done():
			p.mu.Lock()
			p.unregisterWaiterLocked(nil, &registeredWaiter)
			p.mu.Unlock()
			return arden.ErrClosed
		case <-l.connection.conn.Done():
		case <-changed:
		}
	}
}

func (p *Pool[P]) releaseLeaseOperation(lease *Lease[P]) {
	p.mu.Lock()
	if lease.inFlight > 0 {
		lease.inFlight--
	}
	if lease.connection.inFlight > 0 {
		lease.connection.inFlight--
	}
	if lease.connection.inFlight == 0 {
		lease.connection.lastIdle = p.now()
		if lease.closed {
			lease.connection.leased = false
		}
		if lease.connection.draining && !lease.connection.leased {
			lease.connection.retiring = true
			go func() { _ = lease.connection.conn.Close() }()
		}
	}
	for _, endpoint := range p.order {
		p.removeConnectionIfUnusedLocked(endpoint, lease.connection)
	}
	stats := p.statsLocked()
	p.signalLocked()
	p.mu.Unlock()
	endpoint := lease.connection.conn.Endpoint()
	poolDebug(context.Background(), p.loggerFor(endpoint.ID), "ldap lease operation capacity released",
		slog.String("endpoint_id", string(endpoint.ID)),
		slog.String("endpoint_address", endpoint.Address),
		slog.Uint64("connection_id", lease.connection.conn.ID()),
		slog.Int("pool_size", stats.Connections),
		slog.Int("in_flight", stats.InFlight),
		slog.Int("waiters", stats.Waiters),
	)
}

// Close releases the connection after already-started lease operations finish.
// It is idempotent and does not cancel those operations.
func (l *Lease[P]) Close() error {
	l.once.Do(func() {
		p := l.pool
		p.mu.Lock()
		l.closed = true
		if l.inFlight == 0 {
			l.connection.leased = false
			l.connection.lastIdle = p.now()
			if l.connection.draining {
				l.connection.retiring = true
				go func() { _ = l.connection.conn.Close() }()
			}
		}
		for _, endpoint := range p.order {
			p.removeConnectionIfUnusedLocked(endpoint, l.connection)
		}
		stats := p.statsLocked()
		p.signalLocked()
		p.mu.Unlock()
		endpoint := l.connection.conn.Endpoint()
		poolDebug(context.Background(), p.loggerFor(endpoint.ID), "ldap connection lease released",
			slog.String("endpoint_id", string(endpoint.ID)),
			slog.String("endpoint_address", endpoint.Address),
			slog.Uint64("connection_id", l.connection.conn.ID()),
			slog.Int("pool_size", stats.Connections),
			slog.Int("in_flight", stats.InFlight),
			slog.Int("waiters", stats.Waiters),
		)
	})
	return nil
}

func (p *Pool[P]) now() time.Time { return time.Now() }
