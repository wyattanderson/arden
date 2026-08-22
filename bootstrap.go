package arden

import (
	"context"
	"errors"
	"io"
	"sync"
)

const unauthenticatedIdentity = "unauthenticated"

type connectionInitializer func(context.Context, InitializationSession) (any, ConnectionPolicy, error)

// SetupResult is the typed handoff produced after authentication and optional
// endpoint initialization. Conn, Identity, Profile, and Policy describe one
// exact endpoint setup and are suitable for freezing in a pool builder.
type SetupResult[P any] struct {
	Conn     *Conn
	Endpoint Endpoint
	Identity Identity
	Profile  P
	Policy   ConnectionPolicy
}

// Bootstrap dials, authenticates, and invokes initializer before publishing a
// ready connection. Any failure closes the connection. Dial can be used when
// no higher-layer initializer is required.
func Bootstrap[P any](ctx context.Context, dialer *Dialer, endpoint Endpoint, initializer Initializer[P]) (SetupResult[P], error) {
	if initializer == nil {
		return SetupResult[P]{}, errors.New("arden: nil initializer")
	}
	var typedProfile P
	wrapped := func(ctx context.Context, session InitializationSession) (any, ConnectionPolicy, error) {
		profile, policy, err := initializer.Initialize(ctx, session)
		typedProfile = profile
		return profile, policy, err
	}
	conn, _, err := dialer.dial(ctx, endpoint, wrapped)
	if err != nil {
		return SetupResult[P]{}, err
	}
	return SetupResult[P]{
		Conn:     conn,
		Endpoint: endpoint,
		Identity: conn.Identity(),
		Profile:  typedProfile,
		Policy:   conn.Policy(),
	}, nil
}

// DialInitialized is a descriptive alias for Bootstrap.
func DialInitialized[P any](ctx context.Context, dialer *Dialer, endpoint Endpoint, initializer Initializer[P]) (SetupResult[P], error) {
	return Bootstrap(ctx, dialer, endpoint, initializer)
}

func (d *Dialer) initialize(ctx context.Context, conn *Conn, initializer connectionInitializer) (identityResult Identity, profileResult any, resultErr error) {
	defer func() {
		if resultErr != nil {
			conn.retire(resultErr)
		}
	}()
	setupCtx, cancel := context.WithTimeout(ctx, conn.options.InitializationTimeout)
	defer cancel()

	session := newInitializationSession(setupCtx, conn, conn.options.MaxInitializationOperations)
	defer session.deactivate()

	if err := conn.transition(stateAuthenticating); err != nil {
		return Identity{}, nil, setupFailure(conn.endpoint.ID, SetupAuthentication, err)
	}

	identity, err := d.authenticate(setupCtx, conn.endpoint, session)
	if err != nil {
		return Identity{}, nil, setupFailure(conn.endpoint.ID, SetupAuthentication, err)
	}
	if err := setupCtx.Err(); err != nil {
		return Identity{}, nil, setupFailure(conn.endpoint.ID, SetupAuthentication, err)
	}
	if err := identity.Validate(); err != nil {
		return Identity{}, nil, setupFailure(conn.endpoint.ID, SetupAuthentication, err)
	}
	if err := conn.requireInitializationIdle(); err != nil {
		return Identity{}, nil, setupFailure(conn.endpoint.ID, SetupAuthentication, err)
	}

	if err := conn.transition(stateInitializing); err != nil {
		return Identity{}, nil, setupFailure(conn.endpoint.ID, SetupInitialization, err)
	}

	var profile any
	policy := ConnectionPolicy{Cancellation: CancellationConservative}
	if initializer != nil {
		profile, policy, err = initializer(setupCtx, session)
		if err != nil {
			stage := SetupInitialization
			if errors.Is(err, ErrProfileMismatch) {
				stage = SetupProfileMismatch
			}
			return Identity{}, nil, setupFailure(conn.endpoint.ID, stage, err)
		}
	}
	if err := setupCtx.Err(); err != nil {
		return Identity{}, nil, setupFailure(conn.endpoint.ID, SetupInitialization, err)
	}
	if err := policy.Validate(); err != nil {
		return Identity{}, nil, setupFailure(conn.endpoint.ID, SetupInitialization, err)
	}
	if err := conn.requireInitializationIdle(); err != nil {
		return Identity{}, nil, setupFailure(conn.endpoint.ID, SetupInitialization, err)
	}

	// Disable the session before the connection becomes observable. A retained
	// interface can no longer start work after this point.
	session.deactivate()
	if err := conn.markReady(identity, policy); err != nil {
		return Identity{}, nil, setupFailure(conn.endpoint.ID, SetupInitialization, err)
	}
	return identity, profile, nil
}

func (d *Dialer) authenticate(ctx context.Context, endpoint Endpoint, session InitializationSession) (Identity, error) {
	if d.Authentication == nil {
		return Identity{StableID: unauthenticatedIdentity}, nil
	}

	authenticator, beginErr := d.Authentication.Begin(ctx, endpoint)
	if authenticator == nil {
		if beginErr != nil {
			return Identity{}, beginErr
		}
		return Identity{}, errors.New("arden: authentication returned a nil authenticator")
	}
	if beginErr != nil {
		return Identity{}, errors.Join(beginErr, authenticator.Close())
	}

	identity, authErr := authenticator.Authenticate(ctx, session)
	closeErr := authenticator.Close()
	if authErr != nil || closeErr != nil {
		return Identity{}, errors.Join(authErr, closeErr)
	}
	return identity, nil
}

func setupFailure(endpoint EndpointID, stage SetupStage, err error) error {
	var setup *SetupError
	if errors.As(err, &setup) {
		return err
	}
	return &SetupError{Endpoint: endpoint, Stage: stage, Err: err}
}

func (c *Conn) transition(to connectionState) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return c.err
	}
	next, err := advanceConnectionState(c.state, to)
	if err != nil {
		return err
	}
	c.state = next
	return nil
}

func advanceConnectionState(from, to connectionState) (connectionState, error) {
	valid := false
	switch from {
	case stateDialing:
		valid = to == stateTransportSetup
	case stateTransportSetup:
		valid = to == stateAuthenticating
	case stateAuthenticating:
		valid = to == stateInitializing
	case stateInitializing:
		valid = to == stateReady
	case stateReady:
		valid = to == stateDraining
	case stateDraining:
		valid = to == stateClosed
	}
	// A failure can retire the connection from any nonterminal state.
	if to == stateClosed && from != stateClosed {
		valid = true
	}
	if !valid {
		return from, errors.New("arden: invalid connection state transition")
	}
	return to, nil
}

func (c *Conn) requireInitializationIdle() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return c.err
	}
	if len(c.reserved) != 0 || len(c.pending) != 0 || len(c.tombstones) != 0 {
		return errors.New("arden: initialization returned with an operation still active")
	}
	return nil
}

func (c *Conn) markReady(identity Identity, policy ConnectionPolicy) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return c.err
	}
	if c.state != stateInitializing {
		return errors.New("arden: connection did not finish initialization")
	}
	if len(c.reserved) != 0 || len(c.pending) != 0 || len(c.tombstones) != 0 {
		return errors.New("arden: connection has active initialization work")
	}
	next, err := advanceConnectionState(c.state, stateReady)
	if err != nil {
		return err
	}
	c.identity = identity
	c.policy = policy
	c.state = next
	return nil
}

type initializationSession struct {
	conn     *Conn
	setupCtx context.Context
	maxOps   int

	mu         sync.Mutex
	active     bool
	operations int
	streams    map[*initializationStream]struct{}
}

func newInitializationSession(ctx context.Context, conn *Conn, maxOps int) *initializationSession {
	return &initializationSession{
		conn:     conn,
		setupCtx: ctx,
		maxOps:   maxOps,
		active:   true,
		streams:  make(map[*initializationStream]struct{}),
	}
}

func (s *initializationSession) Do(ctx context.Context, op Operation) (ResponseStream, error) {
	if ctx == nil {
		return nil, errors.New("arden: nil initialization operation context")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.active {
		return nil, ErrInitializationClosed
	}
	if err := s.setupCtx.Err(); err != nil {
		return nil, err
	}
	if s.operations == s.maxOps {
		return nil, &LimitError{
			Limit: "initialization operations",
			Value: uint64(s.operations + 1),
			Max:   uint64(s.maxOps),
		}
	}
	s.operations++

	operationCtx, cancel := context.WithCancel(ctx)
	stopSetupCancel := context.AfterFunc(s.setupCtx, cancel)
	stream, err := s.conn.do(operationCtx, op, operationInitialization)
	if err != nil {
		stopSetupCancel()
		cancel()
		return nil, err
	}
	wrapped := &initializationStream{
		session:         s,
		stream:          stream,
		pattern:         op.Responses,
		cancel:          cancel,
		stopSetupCancel: stopSetupCancel,
	}
	s.streams[wrapped] = struct{}{}
	if op.Responses.NoResponse() {
		delete(s.streams, wrapped)
		wrapped.once.Do(wrapped.releaseLocked)
	}
	return wrapped, nil
}

func (s *initializationSession) deactivate() {
	s.mu.Lock()
	if !s.active {
		s.mu.Unlock()
		return
	}
	s.active = false
	streams := make([]*initializationStream, 0, len(s.streams))
	for stream := range s.streams {
		streams = append(streams, stream)
	}
	clear(s.streams)
	s.mu.Unlock()

	for _, stream := range streams {
		stream.release()
	}
}

type initializationStream struct {
	session         *initializationSession
	stream          ResponseStream
	pattern         ResponsePattern
	cancel          context.CancelFunc
	stopSetupCancel func() bool
	once            sync.Once
}

func (s *initializationStream) Next(ctx context.Context) (Response, error) {
	response, err := s.stream.Next(ctx)
	if err != nil {
		if errors.Is(err, io.EOF) {
			s.release()
		}
		return response, err
	}
	if s.pattern.Classify(response.ProtocolID) == ClassificationComplete {
		s.release()
	}
	return response, nil
}

func (s *initializationStream) Close() error {
	err := s.stream.Close()
	s.release()
	return err
}

func (s *initializationStream) release() {
	s.once.Do(func() {
		s.session.mu.Lock()
		delete(s.session.streams, s)
		s.releaseLocked()
		s.session.mu.Unlock()
	})
}

func (s *initializationStream) releaseLocked() {
	s.stopSetupCancel()
	s.cancel()
}
