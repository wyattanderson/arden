package arden

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wyattanderson/arden/ber"
	"github.com/wyattanderson/arden/rfc4511"
)

const (
	defaultQueuedResponses        = 16
	defaultQueuedResponseBytes    = 4 << 20
	defaultUnsolicitedResponses   = 8
	defaultUnsolicitedBytes       = 1 << 20
	defaultCancellationWriteLimit = 5 * time.Second
	defaultCloseTimeout           = 5 * time.Second
	defaultInitializationTimeout  = 30 * time.Second
	defaultInitializationOps      = 16
)

// ConnectionOptions contains the public resource bounds for one connection.
// Zero fields select the documented defaults; zero never means unbounded.
type ConnectionOptions struct {
	BERLimits                   ber.Limits
	MaxQueuedResponses          int
	MaxQueuedResponseBytes      int
	MaxUnsolicitedResponses     int
	MaxUnsolicitedResponseBytes int
	CancellationWriteTimeout    time.Duration
	CloseTimeout                time.Duration
	InitializationTimeout       time.Duration
	MaxInitializationOperations int
}

// DefaultConnectionOptions returns conservative bounds suitable for ordinary
// LDAP operations and streaming searches.
func DefaultConnectionOptions() ConnectionOptions {
	return ConnectionOptions{
		BERLimits:                   ber.DefaultLimits(),
		MaxQueuedResponses:          defaultQueuedResponses,
		MaxQueuedResponseBytes:      defaultQueuedResponseBytes,
		MaxUnsolicitedResponses:     defaultUnsolicitedResponses,
		MaxUnsolicitedResponseBytes: defaultUnsolicitedBytes,
		CancellationWriteTimeout:    defaultCancellationWriteLimit,
		CloseTimeout:                defaultCloseTimeout,
		InitializationTimeout:       defaultInitializationTimeout,
		MaxInitializationOperations: defaultInitializationOps,
	}
}

// Validate checks the options after applying defaults to zero fields.
func (o ConnectionOptions) Validate() error {
	_, err := o.normalized()
	return err
}

func (o ConnectionOptions) normalized() (ConnectionOptions, error) {
	defaults := DefaultConnectionOptions()
	if o.BERLimits == (ber.Limits{}) {
		o.BERLimits = defaults.BERLimits
	}
	if o.MaxQueuedResponses == 0 {
		o.MaxQueuedResponses = defaults.MaxQueuedResponses
	}
	if o.MaxQueuedResponseBytes == 0 {
		o.MaxQueuedResponseBytes = defaults.MaxQueuedResponseBytes
	}
	if o.MaxUnsolicitedResponses == 0 {
		o.MaxUnsolicitedResponses = defaults.MaxUnsolicitedResponses
	}
	if o.MaxUnsolicitedResponseBytes == 0 {
		o.MaxUnsolicitedResponseBytes = defaults.MaxUnsolicitedResponseBytes
	}
	if o.CancellationWriteTimeout == 0 {
		o.CancellationWriteTimeout = defaults.CancellationWriteTimeout
	}
	if o.CloseTimeout == 0 {
		o.CloseTimeout = defaults.CloseTimeout
	}
	if o.InitializationTimeout == 0 {
		o.InitializationTimeout = defaults.InitializationTimeout
	}
	if o.MaxInitializationOperations == 0 {
		o.MaxInitializationOperations = defaults.MaxInitializationOperations
	}
	if err := o.BERLimits.Validate(); err != nil {
		return ConnectionOptions{}, err
	}
	switch {
	case o.MaxQueuedResponses < 0:
		return ConnectionOptions{}, errors.New("arden: MaxQueuedResponses must be positive")
	case o.MaxQueuedResponseBytes < 0:
		return ConnectionOptions{}, errors.New("arden: MaxQueuedResponseBytes must be positive")
	case o.MaxUnsolicitedResponses < 0:
		return ConnectionOptions{}, errors.New("arden: MaxUnsolicitedResponses must be positive")
	case o.MaxUnsolicitedResponseBytes < 0:
		return ConnectionOptions{}, errors.New("arden: MaxUnsolicitedResponseBytes must be positive")
	case o.CancellationWriteTimeout < 0:
		return ConnectionOptions{}, errors.New("arden: CancellationWriteTimeout must be positive")
	case o.CloseTimeout < 0:
		return ConnectionOptions{}, errors.New("arden: CloseTimeout must be positive")
	case o.InitializationTimeout < 0:
		return ConnectionOptions{}, errors.New("arden: InitializationTimeout must be positive")
	case o.MaxInitializationOperations < 0:
		return ConnectionOptions{}, errors.New("arden: MaxInitializationOperations must be positive")
	}
	return o, nil
}

// connectionState is deliberately internal: callers receive a Conn only after
// setup reaches stateReady, and Done/Err describe every terminal state.
type connectionState uint8

const (
	stateDialing connectionState = iota + 1
	stateTransportSetup
	stateAuthenticating
	stateInitializing
	stateReady
	stateDraining
	stateClosed
)

type operationScope uint8

const (
	operationApplication operationScope = iota + 1
	operationInitialization
)

// Dialer establishes LDAP connections. Direct TLS with normal certificate and
// hostname verification is selected by the Endpoint zero value. TLSConfig is
// cloned before its ServerName is set from the endpoint.
type Dialer struct {
	NetDialer      *net.Dialer
	TLSConfig      *tls.Config
	Options        ConnectionOptions
	Authentication Authentication
	// Logger receives debug-level lifecycle records containing only the safe
	// observability fields documented by Arden. A nil Logger disables logging.
	Logger *slog.Logger
	// Tracer receives operation lifecycle hooks. Hook panics are recovered and
	// hook calls made by response routing run outside the socket reader.
	Tracer Tracer
	// TraceMessageIDs opts into message IDs in logs and trace starts. Message
	// IDs are omitted by default because they are intended only for debugging.
	TraceMessageIDs bool
}

// Dial establishes the endpoint's fixed transport and starts its shared LDAP
// framing and routing runtime. It never attempts StartTLS or plaintext
// fallback.
func (d *Dialer) Dial(ctx context.Context, endpoint Endpoint) (*Conn, error) {
	conn, _, err := d.dial(ctx, endpoint, nil)
	return conn, err
}

func (d *Dialer) dial(ctx context.Context, endpoint Endpoint, initializer connectionInitializer) (*Conn, any, error) {
	if ctx == nil {
		return nil, nil, errors.New("arden: nil dial context")
	}
	if err := endpoint.Validate(); err != nil {
		return nil, nil, err
	}
	if d == nil {
		d = new(Dialer)
	}
	options, err := d.Options.normalized()
	if err != nil {
		return nil, nil, err
	}
	if validator, ok := d.Authentication.(AuthenticationEndpointValidator); ok {
		if err := validator.ValidateEndpoint(endpoint); err != nil {
			return nil, nil, &SetupError{Endpoint: endpoint.ID, Stage: SetupAuthentication, Err: err}
		}
	}

	dialStarted := time.Now()
	safeDebug(ctx, d.Logger, "ldap connection dial started",
		slog.String("endpoint_id", string(endpoint.ID)),
		slog.String("endpoint_address", endpoint.Address),
		slog.String("transport", endpoint.Transport.String()),
	)
	state := stateDialing
	netDialer := d.NetDialer
	if netDialer == nil {
		netDialer = new(net.Dialer)
	}
	raw, err := netDialer.DialContext(ctx, "tcp", endpoint.Address)
	if err != nil {
		safeDebug(ctx, d.Logger, "ldap connection dial failed",
			slog.String("endpoint_id", string(endpoint.ID)),
			slog.String("endpoint_address", endpoint.Address),
			slog.Duration("dial_duration", time.Since(dialStarted)),
			slog.String("error_class", errorClass(&TransportError{Stage: StageDial, Err: err})),
		)
		return nil, nil, &TransportError{Stage: StageDial, Outcome: OutcomeNotApplicable, Err: err}
	}
	dialDuration := time.Since(dialStarted)

	transport := raw
	if endpoint.Transport == TransportDirectTLS {
		tlsStarted := time.Now()
		config := new(tls.Config)
		if d.TLSConfig != nil {
			config = d.TLSConfig.Clone()
		}
		config.ServerName = endpoint.ServerName
		tlsConn := tls.Client(raw, config)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = raw.Close()
			safeDebug(ctx, d.Logger, "ldap connection TLS failed",
				slog.String("endpoint_id", string(endpoint.ID)),
				slog.String("endpoint_address", endpoint.Address),
				slog.Duration("dial_duration", dialDuration),
				slog.Duration("tls_duration", time.Since(tlsStarted)),
				slog.String("error_class", errorClass(&TransportError{Stage: StageTLS, Err: err})),
			)
			return nil, nil, &TransportError{Stage: StageTLS, Outcome: OutcomeNotApplicable, Err: err}
		}
		transport = tlsConn
		safeDebug(ctx, d.Logger, "ldap connection TLS completed",
			slog.String("endpoint_id", string(endpoint.ID)),
			slog.String("endpoint_address", endpoint.Address),
			slog.Duration("tls_duration", time.Since(tlsStarted)),
		)
	}
	state, err = advanceConnectionState(state, stateTransportSetup)
	if err != nil {
		_ = transport.Close()
		return nil, nil, err
	}

	conn, err := newObservedConnWithState(transport, endpoint, options, MaxMessageID, state, d.Logger, d.Tracer, d.TraceMessageIDs)
	if err != nil {
		_ = transport.Close()
		return nil, nil, err
	}
	initializationStarted := time.Now()
	_, profile, err := d.initialize(ctx, conn, initializer)
	if err != nil {
		conn.retire(err)
		safeDebug(ctx, d.Logger, "ldap connection initialization failed",
			slog.String("endpoint_id", string(endpoint.ID)),
			slog.String("endpoint_address", endpoint.Address),
			slog.Uint64("connection_id", conn.id),
			slog.Duration("dial_duration", dialDuration),
			slog.Duration("initialization_duration", time.Since(initializationStarted)),
			slog.String("error_class", errorClass(err)),
		)
		return nil, nil, err
	}
	safeDebug(ctx, d.Logger, "ldap connection ready",
		slog.String("endpoint_id", string(endpoint.ID)),
		slog.String("endpoint_address", endpoint.Address),
		slog.Uint64("connection_id", conn.id),
		slog.Duration("dial_duration", dialDuration),
		slog.Duration("initialization_duration", time.Since(initializationStarted)),
	)
	return conn, profile, nil
}

// DialContext is an alias for Dial following the naming used by net.Dialer.
func (d *Dialer) DialContext(ctx context.Context, endpoint Endpoint) (*Conn, error) {
	return d.Dial(ctx, endpoint)
}

// Conn is one concurrent LDAP session. It has one socket reader, serializes
// complete request writes, and routes responses without typed decoding.
type Conn struct {
	transport       net.Conn
	endpoint        Endpoint
	options         ConnectionOptions
	framer          *ber.Framer
	maxID           MessageID
	id              uint64
	logger          *slog.Logger
	tracer          Tracer
	traceMessageIDs bool

	writeToken chan struct{}

	mu         sync.Mutex
	state      connectionState
	closing    bool
	err        error
	identity   Identity
	policy     ConnectionPolicy
	done       chan struct{}
	nextID     MessageID
	idChanged  chan struct{}
	reserved   map[MessageID]struct{}
	pending    map[MessageID]*pendingOperation
	tombstones map[MessageID]ResponsePattern

	unsolicited      []Response
	unsolicitedBytes int
	unsolicitedReady chan struct{}
}

// Connection is the descriptive name for Conn. Conn is retained as the short
// Go-style spelling used by Dialer.
type Connection = Conn

type pendingOperation struct {
	conn          *Conn
	id            MessageID
	pattern       ResponsePattern
	mode          CancellationMode
	ctx           context.Context
	observer      *operationObserver
	requestBytes  uint64
	responseBytes uint64
	responses     uint64
	firstResponse bool
	writeObserved chan struct{}

	queue        []Response
	queuedBytes  int
	deliveryErr  error
	canceled     bool
	terminal     bool
	abandoning   bool
	writeStarted bool

	ready         chan struct{}
	lifecycleDone chan struct{}
	lifecycleOnce sync.Once
}

func newConn(transport net.Conn, endpoint Endpoint, options ConnectionOptions, maxID MessageID) (*Conn, error) {
	return newConnWithState(transport, endpoint, options, maxID, stateReady)
}

func newConnWithState(transport net.Conn, endpoint Endpoint, options ConnectionOptions, maxID MessageID, state connectionState) (*Conn, error) {
	return newObservedConnWithState(transport, endpoint, options, maxID, state, nil, nil, false)
}

var nextConnectionID atomic.Uint64

func newObservedConnWithState(transport net.Conn, endpoint Endpoint, options ConnectionOptions, maxID MessageID, state connectionState, logger *slog.Logger, tracer Tracer, traceMessageIDs bool) (*Conn, error) {
	if transport == nil {
		return nil, errors.New("arden: nil connection transport")
	}
	if maxID <= 0 || maxID > MaxMessageID {
		return nil, errors.New("arden: invalid message ID limit")
	}
	if state != stateTransportSetup && state != stateReady {
		return nil, errors.New("arden: invalid initial connection state")
	}
	framer, err := ber.NewFramer(transport, options.BERLimits)
	if err != nil {
		return nil, err
	}
	c := &Conn{
		transport:        transport,
		endpoint:         endpoint,
		options:          options,
		framer:           framer,
		maxID:            maxID,
		id:               nextConnectionID.Add(1),
		logger:           logger,
		tracer:           tracer,
		traceMessageIDs:  traceMessageIDs,
		state:            state,
		identity:         Identity{StableID: "unauthenticated"},
		policy:           ConnectionPolicy{Cancellation: CancellationConservative},
		writeToken:       make(chan struct{}, 1),
		done:             make(chan struct{}),
		idChanged:        make(chan struct{}),
		reserved:         make(map[MessageID]struct{}),
		pending:          make(map[MessageID]*pendingOperation),
		tombstones:       make(map[MessageID]ResponsePattern),
		unsolicitedReady: make(chan struct{}, 1),
	}
	c.writeToken <- struct{}{}
	go c.readLoop()
	return c, nil
}

// Endpoint returns the immutable endpoint used to create the session.
func (c *Conn) Endpoint() Endpoint { return c.endpoint }

// ID returns a process-scoped connection identifier suitable for logs and
// traces. It is not stable across process restarts.
func (c *Conn) ID() uint64 { return c.id }

// Identity returns the stable, nonsecret authentication identity selected
// during setup.
func (c *Conn) Identity() Identity {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.identity
}

// Policy returns the core setup policy frozen when the connection became
// ready.
func (c *Conn) Policy() ConnectionPolicy {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.policy
}

// Done is closed when the connection is retired or closed.
func (c *Conn) Done() <-chan struct{} { return c.done }

// Err returns the terminal connection error, or nil while the connection is
// active.
func (c *Conn) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

// Do validates, encodes, registers, and writes one binary LDAP operation.
func (c *Conn) Do(ctx context.Context, op Operation) (ResponseStream, error) {
	return c.do(ctx, op, operationApplication)
}

func (c *Conn) do(ctx context.Context, op Operation, scope operationScope) (ResponseStream, error) {
	queuedAt := time.Now()
	if ctx == nil {
		return nil, errors.New("arden: nil operation context")
	}
	if err := op.Validate(); err != nil {
		return nil, err
	}
	if scope == operationApplication && isAssociationChanging(op.Protocol.ProtocolIdentifier()) {
		return nil, ErrAssociationChange
	}

	id, err := c.reserveMessageID(ctx, scope)
	if err != nil {
		return nil, err
	}
	message, err := encodeLDAPRequest(id, op, c.options.BERLimits)
	if err != nil {
		c.releaseReserved(id)
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		c.releaseReserved(id)
		return nil, &TransportError{Stage: StageWrite, Outcome: OutcomeDefinitelyUnsent, Err: err}
	}
	traceMessageID := MessageID(0)
	if c.traceMessageIDs {
		traceMessageID = id
	}
	traceCtx, observer := startOperationObserver(ctx, c.tracer, c.logger, TraceStart{
		Endpoint:        c.endpoint.ID,
		EndpointAddress: c.endpoint.Address,
		Connection:      c.id,
		Label:           op.Metadata.Label,
		ApplicationTag:  op.Protocol.ProtocolIdentifier(),
		RequestID:       op.Protocol.ProtocolIdentifier(),
		MessageID:       traceMessageID,
	}, queuedAt)
	observer.event(TraceEvent{Kind: TraceQueued, At: time.Now()})
	p := &pendingOperation{
		conn:          c,
		id:            id,
		pattern:       op.Responses,
		mode:          op.Cancellation,
		ctx:           traceCtx,
		observer:      observer,
		requestBytes:  uint64(len(message)),
		writeObserved: make(chan struct{}),
		ready:         make(chan struct{}, 1),
		lifecycleDone: make(chan struct{}),
	}
	if err := c.installPending(p, scope); err != nil {
		c.releaseReserved(id)
		observer.end(TraceEnd{At: time.Now(), RequestBytes: uint64(len(message)), ErrorClass: errorClass(err)})
		return nil, err
	}

	written, err := c.writeRequest(traceCtx, p, message)
	if err != nil {
		if written == 0 && !errors.Is(err, ErrAmbiguousOutcome) {
			c.removeDefinitelyUnsent(p, err)
		}
		return nil, err
	}
	observer.event(TraceEvent{Kind: TraceWritten, At: time.Now(), Bytes: uint64(written)})
	close(p.writeObserved)

	stream := &responseStream{pending: p}
	if op.Responses.NoResponse() {
		c.completeNoResponse(p)
		return stream, nil
	}
	go c.watchOperation(p)
	return stream, nil
}

func isAssociationChanging(id ber.Identifier) bool {
	return id == rfc4511.BindRequestIdentifier() || id == rfc4511.UnbindRequestIdentifier()
}

func encodeLDAPRequest(id MessageID, op Operation, limits ber.Limits) ([]byte, error) {
	protocol, err := op.Protocol.AppendBER(nil)
	if err != nil {
		return nil, err
	}
	element, err := ber.DecodeElement(protocol, limits)
	if err != nil {
		return nil, fmt.Errorf("arden: request protocolOp: %w", err)
	}
	if got, want := element.Identifier, op.Protocol.ProtocolIdentifier(); got != want {
		return nil, fmt.Errorf("arden: encoded request identifier %s does not match declared identifier %s", got, want)
	}

	contents, err := ber.AppendInteger(nil, int64(id))
	if err != nil {
		return nil, err
	}
	contents = append(contents, protocol...)
	if len(op.Controls) != 0 {
		controlContents := make([]byte, 0)
		for i, control := range op.Controls {
			encoded, err := control.AppendBER(nil)
			if err != nil {
				return nil, fmt.Errorf("arden: control %d: %w", i, err)
			}
			element, err := ber.DecodeElement(encoded, limits)
			if err != nil {
				return nil, fmt.Errorf("arden: control %d: %w", i, err)
			}
			if element.Identifier != ber.SequenceIdentifier {
				return nil, fmt.Errorf("arden: control %d identifier %s is not a SEQUENCE", i, element.Identifier)
			}
			controlContents = append(controlContents, encoded...)
		}
		contents, err = ber.AppendConstructed(contents, controlsIdentifier, controlContents)
		if err != nil {
			return nil, err
		}
	}
	message, err := ber.AppendSequence(nil, contents)
	if err != nil {
		return nil, err
	}
	if len(message) > limits.MaxFrameBytes {
		return nil, &LimitError{Limit: "request frame bytes", Value: uint64(len(message)), Max: uint64(limits.MaxFrameBytes)}
	}
	return message, nil
}

func (c *Conn) reserveMessageID(ctx context.Context, scope operationScope) (MessageID, error) {
	for {
		c.mu.Lock()
		if c.err != nil || c.closing {
			err := c.err
			if err == nil {
				err = ErrClosed
			}
			c.mu.Unlock()
			return 0, err
		}
		if !c.scopeAllowedLocked(scope) {
			c.mu.Unlock()
			if scope == operationApplication {
				return 0, ErrConnectionNotReady
			}
			return 0, ErrInitializationClosed
		}
		if id, ok := c.tryReserveMessageIDLocked(); ok {
			c.mu.Unlock()
			return id, nil
		}
		changed, done := c.idChanged, c.done
		c.mu.Unlock()

		select {
		case <-ctx.Done():
			return 0, &TransportError{Stage: StageWrite, Outcome: OutcomeDefinitelyUnsent, Err: ctx.Err()}
		case <-changed:
		case <-done:
			return 0, c.Err()
		}
	}
}

func (c *Conn) tryReserveMessageIDLocked() (MessageID, bool) {
	if int64(len(c.reserved))+int64(len(c.pending))+int64(len(c.tombstones)) >= int64(c.maxID) {
		return 0, false
	}
	for range c.maxID {
		c.nextID++
		if c.nextID > c.maxID || c.nextID <= 0 {
			c.nextID = 1
		}
		id := c.nextID
		if _, ok := c.reserved[id]; ok {
			continue
		}
		if _, ok := c.pending[id]; ok {
			continue
		}
		if _, ok := c.tombstones[id]; ok {
			continue
		}
		c.reserved[id] = struct{}{}
		return id, true
	}
	return 0, false
}

func (c *Conn) releaseReserved(id MessageID) {
	c.mu.Lock()
	if _, ok := c.reserved[id]; ok {
		delete(c.reserved, id)
		c.signalIDChangedLocked()
	}
	c.mu.Unlock()
}

func (c *Conn) installPending(p *pendingOperation, scope operationScope) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil || c.closing {
		if c.err != nil {
			return c.err
		}
		return ErrClosed
	}
	if !c.scopeAllowedLocked(scope) {
		if scope == operationApplication {
			return ErrConnectionNotReady
		}
		return ErrInitializationClosed
	}
	if _, ok := c.reserved[p.id]; !ok {
		return errors.New("arden: message ID reservation was lost")
	}
	delete(c.reserved, p.id)
	c.pending[p.id] = p
	return nil
}

func (c *Conn) scopeAllowedLocked(scope operationScope) bool {
	switch scope {
	case operationApplication:
		return c.state == stateReady
	case operationInitialization:
		return c.state == stateAuthenticating || c.state == stateInitializing
	default:
		return false
	}
}

func (c *Conn) signalIDChangedLocked() {
	close(c.idChanged)
	c.idChanged = make(chan struct{})
}

func (c *Conn) removeDefinitelyUnsent(p *pendingOperation, err error) {
	c.mu.Lock()
	if c.pending[p.id] == p {
		delete(c.pending, p.id)
		p.terminal = true
		p.finishLifecycle(err)
		c.signalIDChangedLocked()
		p.signalReady()
	}
	c.mu.Unlock()
}

func (c *Conn) completeNoResponse(p *pendingOperation) {
	c.mu.Lock()
	if c.pending[p.id] == p {
		delete(c.pending, p.id)
		p.terminal = true
		p.finishLifecycle(nil)
		c.signalIDChangedLocked()
		p.signalReady()
	}
	c.mu.Unlock()
}

func (p *pendingOperation) signalReady() {
	select {
	case p.ready <- struct{}{}:
	default:
	}
}

func (p *pendingOperation) finishLifecycle(err error) {
	p.lifecycleOnce.Do(func() {
		close(p.lifecycleDone)
		p.observer.end(TraceEnd{
			At:            time.Now(),
			RequestBytes:  p.requestBytes,
			ResponseBytes: p.responseBytes,
			Responses:     p.responses,
			ErrorClass:    errorClass(err),
		})
	})
}

type responseStream struct {
	pending *pendingOperation
	once    sync.Once
}

// Done closes when the protocol operation no longer occupies a message ID.
func (s *responseStream) Done() <-chan struct{} { return s.pending.lifecycleDone }

func (s *responseStream) Next(ctx context.Context) (Response, error) {
	if ctx == nil {
		return Response{}, errors.New("arden: nil response context")
	}
	p := s.pending
	if err := p.ctx.Err(); err != nil {
		p.conn.cancelOperation(p, err)
	}
	for {
		p.conn.mu.Lock()
		if len(p.queue) != 0 {
			response := p.queue[0]
			p.queue[0] = Response{}
			p.queue = p.queue[1:]
			p.queuedBytes -= len(response.Bytes)
			p.conn.mu.Unlock()
			return response, nil
		}
		if p.deliveryErr != nil {
			err := p.deliveryErr
			p.conn.mu.Unlock()
			return Response{}, err
		}
		if p.terminal {
			p.conn.mu.Unlock()
			return Response{}, io.EOF
		}
		ready := p.ready
		p.conn.mu.Unlock()

		select {
		case <-ready:
		case <-ctx.Done():
			return Response{}, ctx.Err()
		case <-p.ctx.Done():
			p.conn.cancelOperation(p, p.ctx.Err())
		case <-p.conn.done:
		}
	}
}

func (s *responseStream) Close() error {
	s.once.Do(func() { s.pending.conn.cancelOperation(s.pending, ErrClosed) })
	return nil
}

func (c *Conn) watchOperation(p *pendingOperation) {
	select {
	case <-p.ctx.Done():
		c.cancelOperation(p, p.ctx.Err())
	case <-p.lifecycleDone:
	case <-c.done:
	}
}

type cancelAction uint8

const (
	cancelActionNone cancelAction = iota
	cancelActionAbandon
	cancelActionClose
)

func (c *Conn) cancelOperation(p *pendingOperation, reason error) {
	action := cancelActionNone
	c.mu.Lock()
	// A terminal response atomically completes the operation. Cancellation
	// observed after that point must not erase an already-owned result.
	if p.terminal {
		c.mu.Unlock()
		return
	}
	if p.deliveryErr == nil {
		p.deliveryErr = reason
		for i := range p.queue {
			p.queue[i] = Response{}
		}
		p.queue = nil
		p.queuedBytes = 0
		p.canceled = true
		p.observer.event(TraceEvent{Kind: TraceCanceled, At: time.Now(), Bytes: p.responseBytes, Responses: p.responses})
		p.signalReady()
	}
	if c.pending[p.id] == p && !p.abandoning {
		switch p.mode {
		case CancelAbandon:
			p.abandoning = true
			action = cancelActionAbandon
		case CancelClose:
			action = cancelActionClose
		}
	}
	c.mu.Unlock()

	switch action {
	case cancelActionAbandon:
		go c.sendAbandon(p)
	case cancelActionClose:
		c.retire(ErrClosed)
	}
}

func (c *Conn) writeRequest(ctx context.Context, p *pendingOperation, message []byte) (int, error) {
	if err := c.acquireWriter(ctx); err != nil {
		return 0, err
	}
	defer c.releaseWriter()
	c.mu.Lock()
	if c.pending[p.id] == p {
		p.writeStarted = true
	}
	c.mu.Unlock()
	return c.writeAll(ctx, message)
}

func (c *Conn) acquireWriter(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return &TransportError{Stage: StageWrite, Outcome: OutcomeDefinitelyUnsent, Err: ctx.Err()}
	case <-c.done:
		err := c.Err()
		return &TransportError{Stage: StageWrite, Outcome: OutcomeDefinitelyUnsent, Err: err}
	case <-c.writeToken:
	}
	if err := ctx.Err(); err != nil {
		c.releaseWriter()
		return &TransportError{Stage: StageWrite, Outcome: OutcomeDefinitelyUnsent, Err: err}
	}
	c.mu.Lock()
	err := c.err
	closing := c.closing
	c.mu.Unlock()
	if err != nil || closing {
		c.releaseWriter()
		if err == nil {
			err = ErrClosed
		}
		return &TransportError{Stage: StageWrite, Outcome: OutcomeDefinitelyUnsent, Err: err}
	}
	return nil
}

func (c *Conn) releaseWriter() { c.writeToken <- struct{}{} }

func (c *Conn) writeAll(ctx context.Context, message []byte) (int, error) {
	total := 0
	for total < len(message) {
		if err := ctx.Err(); err != nil {
			outcome := OutcomeDefinitelyUnsent
			if total != 0 {
				outcome = OutcomeAmbiguous
			}
			transportErr := &TransportError{Stage: StageWrite, Outcome: outcome, Err: err}
			if outcome == OutcomeAmbiguous {
				c.retire(transportErr)
			}
			return total, transportErr
		}

		// Closing the connection is the only portable way to interrupt an
		// in-progress Write without applying one operation's deadline to the
		// shared socket. If cancellation wins this race, the outcome is
		// conservatively ambiguous.
		var writeState atomic.Uint32
		stop := context.AfterFunc(ctx, func() {
			if writeState.CompareAndSwap(0, 2) {
				c.retire(&TransportError{Stage: StageWrite, Outcome: OutcomeAmbiguous, Err: ctx.Err()})
			}
		})
		n, err := c.transport.Write(message[total:])
		writeCompleted := writeState.CompareAndSwap(0, 1)
		stop()
		if n > 0 {
			total += n
		}
		if !writeCompleted {
			transportErr := &TransportError{Stage: StageWrite, Outcome: OutcomeAmbiguous, Err: ctx.Err()}
			return total, transportErr
		}
		if err == nil && n == 0 {
			err = io.ErrNoProgress
		}
		if err != nil {
			outcome := OutcomeDefinitelyUnsent
			if total != 0 || ctx.Err() != nil {
				outcome = OutcomeAmbiguous
			}
			cause := err
			if ctx.Err() != nil {
				cause = ctx.Err()
			}
			transportErr := &TransportError{Stage: StageWrite, Outcome: outcome, Err: cause}
			c.retire(transportErr)
			return total, transportErr
		}
	}
	return total, nil
}

func (c *Conn) sendAbandon(target *pendingOperation) {
	c.mu.Lock()
	if c.pending[target.id] != target || c.err != nil || c.closing {
		c.mu.Unlock()
		return
	}
	abandonID, ok := c.tryReserveMessageIDLocked()
	c.mu.Unlock()
	if !ok {
		c.retire(&LimitError{Limit: "message IDs", Value: uint64(c.maxID) + 1, Max: uint64(c.maxID)})
		return
	}

	message, err := encodeAbandonRequest(abandonID, target.id)
	if err != nil {
		c.releaseReserved(abandonID)
		c.retire(&ProtocolError{Kind: ProtocolEnvelope, MessageID: target.id, Err: err})
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), c.options.CancellationWriteTimeout)
	defer cancel()
	if err := c.acquireWriter(ctx); err != nil {
		c.releaseReserved(abandonID)
		if !errors.Is(err, ErrClosed) {
			c.retire(err)
		}
		return
	}

	c.mu.Lock()
	if c.pending[target.id] != target || c.err != nil || c.closing {
		c.mu.Unlock()
		c.releaseWriter()
		c.releaseReserved(abandonID)
		return
	}
	delete(c.pending, target.id)
	c.tombstones[target.id] = target.pattern
	target.finishLifecycle(target.deliveryErr)
	target.signalReady()
	c.mu.Unlock()

	_, err = c.writeAll(ctx, message)
	c.releaseWriter()
	c.releaseReserved(abandonID)
	if err != nil {
		c.retire(err)
	}
}

func encodeAbandonRequest(messageID, target MessageID) ([]byte, error) {
	protocolValue, err := (&rfc4511.AbandonRequest{Target: target}).AppendBER(nil)
	if err != nil {
		return nil, err
	}
	return encodeInternalRequest(messageID, protocolValue)
}

func encodeInternalRequest(messageID MessageID, protocol []byte) ([]byte, error) {
	contents, err := ber.AppendInteger(nil, int64(messageID))
	if err != nil {
		return nil, err
	}
	contents = append(contents, protocol...)
	return ber.AppendSequence(nil, contents)
}

func (c *Conn) readLoop() {
	for {
		message, err := c.framer.Next()
		if err != nil {
			c.retire(c.classifyReadError(err))
			return
		}
		response, err := parseOwnedResponse(message, c.options.BERLimits)
		if err != nil {
			c.retire(&ProtocolError{Kind: ProtocolEnvelope, Err: translateBERLimit(err)})
			return
		}
		if err := c.route(response); err != nil {
			c.retire(err)
			return
		}
	}
}

func (c *Conn) classifyReadError(err error) error {
	c.mu.Lock()
	closing := c.closing
	c.mu.Unlock()
	if closing || errors.Is(err, net.ErrClosed) {
		return ErrClosed
	}
	if errors.Is(err, io.EOF) {
		return &TransportError{Stage: StagePeerClose, Outcome: OutcomeNotApplicable, Err: io.EOF}
	}
	var decodeErr *ber.DecodeError
	if errors.As(err, &decodeErr) {
		return &ProtocolError{Kind: ProtocolFraming, Err: translateBERLimit(err)}
	}
	return &TransportError{Stage: StageRead, Outcome: OutcomeNotApplicable, Err: err}
}

func translateBERLimit(err error) error {
	var limit *ber.LimitError
	if !errors.As(err, &limit) {
		return err
	}
	return &LimitError{Limit: "BER " + limit.Limit, Value: limit.Value, Max: limit.Max}
}

func (c *Conn) route(response Response) error {
	if response.MessageID == 0 {
		return c.routeUnsolicited(response)
	}

	var action cancelAction
	c.mu.Lock()
	p := c.pending[response.MessageID]
	if p == nil {
		pattern, tombstoned := c.tombstones[response.MessageID]
		if !tombstoned {
			c.mu.Unlock()
			return &ProtocolError{Kind: ProtocolUnexpectedMessageID, MessageID: response.MessageID, Got: response.ProtocolID}
		}
		classification := pattern.Classify(response.ProtocolID)
		c.mu.Unlock()
		if classification == ClassificationInvalid {
			return &ProtocolError{Kind: ProtocolUnexpectedIdentifier, MessageID: response.MessageID, Got: response.ProtocolID}
		}
		return nil
	}
	select {
	case <-p.writeObserved:
	case <-c.done:
		c.mu.Unlock()
		return nil
	default:
		written := p.writeObserved
		done := c.done
		c.mu.Unlock()
		select {
		case <-written:
			return c.route(response)
		case <-done:
			return nil
		}
	}

	classification := p.pattern.Classify(response.ProtocolID)
	if classification == ClassificationInvalid {
		c.mu.Unlock()
		return &ProtocolError{Kind: ProtocolUnexpectedIdentifier, MessageID: response.MessageID, Got: response.ProtocolID}
	}
	p.responseBytes += uint64(len(response.Bytes))
	p.responses++
	if !p.firstResponse {
		p.firstResponse = true
		p.observer.event(TraceEvent{Kind: TraceFirstResponse, At: time.Now(), Bytes: p.responseBytes, Responses: p.responses})
	}
	if classification == ClassificationComplete {
		delete(c.pending, p.id)
		p.terminal = true
		c.signalIDChangedLocked()
	}
	if !p.canceled {
		if len(p.queue) == c.options.MaxQueuedResponses || p.queuedBytes+len(response.Bytes) > c.options.MaxQueuedResponseBytes {
			limit := &LimitError{Limit: "operation response queue bytes", Value: uint64(p.queuedBytes + len(response.Bytes)), Max: uint64(c.options.MaxQueuedResponseBytes)}
			if len(p.queue) == c.options.MaxQueuedResponses {
				limit = &LimitError{Limit: "operation response queue messages", Value: uint64(len(p.queue) + 1), Max: uint64(c.options.MaxQueuedResponses)}
			}
			p.deliveryErr = limit
			for i := range p.queue {
				p.queue[i] = Response{}
			}
			p.queue = nil
			p.queuedBytes = 0
			p.canceled = true
			if classification != ClassificationComplete {
				switch p.mode {
				case CancelAbandon:
					p.abandoning = true
					action = cancelActionAbandon
				case CancelClose:
					action = cancelActionClose
				}
			}
		} else {
			p.queue = append(p.queue, response)
			p.queuedBytes += len(response.Bytes)
		}
	}
	p.signalReady()
	if classification == ClassificationComplete {
		p.finishLifecycle(p.deliveryErr)
	}
	c.mu.Unlock()

	switch action {
	case cancelActionAbandon:
		go c.sendAbandon(p)
	case cancelActionClose:
		return &LimitError{Limit: "operation response queue", Value: 1, Max: 0}
	}
	return nil
}

func (c *Conn) routeUnsolicited(response Response) error {
	if response.ProtocolID != rfc4511.ExtendedResponseIdentifier() {
		return &ProtocolError{Kind: ProtocolUnexpectedIdentifier, MessageID: 0, Got: response.ProtocolID}
	}
	notice, err := parseNotice(response.Protocol, c.options.BERLimits)
	if err != nil {
		return &ProtocolError{Kind: ProtocolEnvelope, MessageID: 0, Got: response.ProtocolID, Err: translateBERLimit(err)}
	}
	if notice != nil {
		return notice
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.unsolicited) == c.options.MaxUnsolicitedResponses {
		return &LimitError{Limit: "unsolicited response queue messages", Value: uint64(len(c.unsolicited) + 1), Max: uint64(c.options.MaxUnsolicitedResponses)}
	}
	if c.unsolicitedBytes+len(response.Bytes) > c.options.MaxUnsolicitedResponseBytes {
		return &LimitError{Limit: "unsolicited response queue bytes", Value: uint64(c.unsolicitedBytes + len(response.Bytes)), Max: uint64(c.options.MaxUnsolicitedResponseBytes)}
	}
	c.unsolicited = append(c.unsolicited, response)
	c.unsolicitedBytes += len(response.Bytes)
	select {
	case c.unsolicitedReady <- struct{}{}:
	default:
	}
	return nil
}

const noticeOfDisconnectionOID rfc4511.LDAPOID = "1.3.6.1.4.1.1466.20036"

func parseNotice(protocol []byte, limits ber.Limits) (*NoticeError, error) {
	r, err := ber.NewReader(protocol, limits)
	if err != nil {
		return nil, err
	}
	var response rfc4511.ExtendedResponse
	if err := response.UnmarshalBER(r); err != nil {
		return nil, err
	}
	if err := r.RequireEmpty(); err != nil {
		return nil, err
	}
	if !response.HasResponseName || response.ResponseName != noticeOfDisconnectionOID {
		return nil, nil
	}
	return &NoticeError{
		ResultCode: int64(response.Result.ResultCode),
		Diagnostic: []byte(response.Result.DiagnosticMessage),
	}, nil
}

// NextUnsolicited returns the next non-notice unsolicited ExtendedResponse.
// A Notice of Disconnection is returned as the connection's terminal error.
func (c *Conn) NextUnsolicited(ctx context.Context) (Response, error) {
	if ctx == nil {
		return Response{}, errors.New("arden: nil unsolicited-response context")
	}
	for {
		c.mu.Lock()
		if len(c.unsolicited) != 0 {
			response := c.unsolicited[0]
			c.unsolicited[0] = Response{}
			c.unsolicited = c.unsolicited[1:]
			c.unsolicitedBytes -= len(response.Bytes)
			c.mu.Unlock()
			return response, nil
		}
		if c.err != nil {
			err := c.err
			c.mu.Unlock()
			return Response{}, err
		}
		ready, done := c.unsolicitedReady, c.done
		c.mu.Unlock()
		select {
		case <-ready:
		case <-done:
		case <-ctx.Done():
			return Response{}, ctx.Err()
		}
	}
}

// Close sends an LDAP Unbind when the writer is available, then closes the
// transport. It is idempotent and bounds graceful shutdown by CloseTimeout.
func (c *Conn) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), c.options.CloseTimeout)
	defer cancel()
	return c.CloseContext(ctx)
}

// CloseContext is the context-aware form of Close. Once it begins, no new
// operations are accepted, even if the Unbind write cannot complete.
func (c *Conn) CloseContext(ctx context.Context) error {
	if ctx == nil {
		return errors.New("arden: nil close context")
	}
	c.mu.Lock()
	if c.err != nil {
		alreadyClosed := c.closing || errors.Is(c.err, ErrClosed)
		err := c.err
		c.mu.Unlock()
		if alreadyClosed {
			return nil
		}
		return err
	}
	if c.closing {
		done := c.done
		c.mu.Unlock()
		select {
		case <-done:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	c.closing = true
	if c.state != stateClosed {
		c.state = stateDraining
	}
	c.mu.Unlock()

	var closeErr error
	select {
	case <-c.writeToken:
		c.mu.Lock()
		id, ok := c.tryReserveMessageIDLocked()
		c.mu.Unlock()
		if ok {
			protocolValue, _ := (&rfc4511.UnbindRequest{}).AppendBER(nil)
			message, _ := encodeInternalRequest(id, protocolValue)
			_, closeErr = c.writeAll(ctx, message)
			c.releaseReserved(id)
		}
		c.releaseWriter()
	case <-ctx.Done():
		closeErr = ctx.Err()
	case <-c.done:
	}
	_ = c.transport.Close()
	c.retire(ErrClosed)
	if closeErr != nil && !errors.Is(closeErr, ErrClosed) {
		return closeErr
	}
	return nil
}

func (c *Conn) retire(err error) {
	if err == nil {
		err = ErrClosed
	}
	c.mu.Lock()
	if c.err != nil {
		c.mu.Unlock()
		return
	}
	if c.closing {
		err = ErrClosed
	}
	c.err = err
	c.state = stateClosed
	close(c.done)
	_ = c.transport.Close()
	for id := range c.reserved {
		delete(c.reserved, id)
	}
	for id, p := range c.pending {
		delete(c.pending, id)
		if p.deliveryErr == nil {
			p.deliveryErr = operationRetirementError(p, err)
		}
		p.observer.event(TraceEvent{Kind: TraceConnectionRetired, At: time.Now(), Bytes: p.responseBytes, Responses: p.responses})
		p.terminal = true
		p.finishLifecycle(p.deliveryErr)
		p.signalReady()
	}
	clear(c.tombstones)
	c.signalIDChangedLocked()
	select {
	case c.unsolicitedReady <- struct{}{}:
	default:
	}
	c.mu.Unlock()
	safeDebug(context.Background(), c.logger, "ldap connection retired",
		slog.String("endpoint_id", string(c.endpoint.ID)),
		slog.String("endpoint_address", c.endpoint.Address),
		slog.Uint64("connection_id", c.id),
		slog.String("error_class", errorClass(err)),
	)
}

func operationRetirementError(p *pendingOperation, err error) error {
	var transportErr *TransportError
	if !errors.As(err, &transportErr) {
		return err
	}
	outcome := OutcomeDefinitelyUnsent
	if p.writeStarted {
		outcome = OutcomeAmbiguous
	}
	return &TransportError{Stage: transportErr.Stage, Outcome: outcome, Err: transportErr.Err}
}
