package arden

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wyattanderson/arden/ber"
)

const (
	defaultQueuedResponses        = 16
	defaultQueuedResponseBytes    = 4 << 20
	defaultUnsolicitedResponses   = 8
	defaultUnsolicitedBytes       = 1 << 20
	defaultCancellationWriteLimit = 5 * time.Second
	defaultCloseTimeout           = 5 * time.Second
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
	}
	return o, nil
}

// Dialer establishes LDAP connections. Direct TLS with normal certificate and
// hostname verification is selected by the Endpoint zero value. TLSConfig is
// cloned before its ServerName is set from the endpoint.
type Dialer struct {
	NetDialer *net.Dialer
	TLSConfig *tls.Config
	Options   ConnectionOptions
}

// Dial establishes the endpoint's fixed transport and starts its shared LDAP
// framing and routing runtime. It never attempts StartTLS or plaintext
// fallback.
func (d *Dialer) Dial(ctx context.Context, endpoint Endpoint) (*Conn, error) {
	if ctx == nil {
		return nil, errors.New("arden: nil dial context")
	}
	if err := endpoint.Validate(); err != nil {
		return nil, err
	}
	if d == nil {
		d = new(Dialer)
	}
	options, err := d.Options.normalized()
	if err != nil {
		return nil, err
	}

	netDialer := d.NetDialer
	if netDialer == nil {
		netDialer = new(net.Dialer)
	}
	raw, err := netDialer.DialContext(ctx, "tcp", endpoint.Address)
	if err != nil {
		return nil, &TransportError{Stage: StageDial, Outcome: OutcomeNotApplicable, Err: err}
	}

	transport := raw
	if endpoint.Transport == TransportDirectTLS {
		config := new(tls.Config)
		if d.TLSConfig != nil {
			config = d.TLSConfig.Clone()
		}
		config.ServerName = endpoint.ServerName
		tlsConn := tls.Client(raw, config)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = raw.Close()
			return nil, &TransportError{Stage: StageTLS, Outcome: OutcomeNotApplicable, Err: err}
		}
		transport = tlsConn
	}

	conn, err := newConn(transport, endpoint, options, MaxMessageID)
	if err != nil {
		_ = transport.Close()
		return nil, err
	}
	return conn, nil
}

// DialContext is an alias for Dial following the naming used by net.Dialer.
func (d *Dialer) DialContext(ctx context.Context, endpoint Endpoint) (*Conn, error) {
	return d.Dial(ctx, endpoint)
}

// Conn is one concurrent LDAP session. It has one socket reader, serializes
// complete request writes, and routes responses without typed decoding.
type Conn struct {
	transport net.Conn
	endpoint  Endpoint
	options   ConnectionOptions
	framer    *ber.Framer
	maxID     MessageID

	writeToken chan struct{}

	mu         sync.Mutex
	closing    bool
	err        error
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
	conn    *Conn
	id      MessageID
	pattern ResponsePattern
	mode    CancellationMode
	ctx     context.Context

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
	if transport == nil {
		return nil, errors.New("arden: nil connection transport")
	}
	if maxID <= 0 || maxID > MaxMessageID {
		return nil, errors.New("arden: invalid message ID limit")
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
	if ctx == nil {
		return nil, errors.New("arden: nil operation context")
	}
	if err := op.Validate(); err != nil {
		return nil, err
	}

	id, err := c.reserveMessageID(ctx)
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
	p := &pendingOperation{
		conn:          c,
		id:            id,
		pattern:       op.Responses,
		mode:          op.Cancellation,
		ctx:           ctx,
		ready:         make(chan struct{}, 1),
		lifecycleDone: make(chan struct{}),
	}
	if err := c.installPending(p); err != nil {
		c.releaseReserved(id)
		return nil, err
	}

	written, err := c.writeRequest(ctx, p, message)
	if err != nil {
		if written == 0 && !errors.Is(err, ErrAmbiguousOutcome) {
			c.removeDefinitelyUnsent(p)
		}
		return nil, err
	}

	stream := &responseStream{pending: p}
	if op.Responses.NoResponse() {
		c.completeNoResponse(p)
		return stream, nil
	}
	go c.watchOperation(p)
	return stream, nil
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

func (c *Conn) reserveMessageID(ctx context.Context) (MessageID, error) {
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

func (c *Conn) installPending(p *pendingOperation) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil || c.closing {
		if c.err != nil {
			return c.err
		}
		return ErrClosed
	}
	if _, ok := c.reserved[p.id]; !ok {
		return errors.New("arden: message ID reservation was lost")
	}
	delete(c.reserved, p.id)
	c.pending[p.id] = p
	return nil
}

func (c *Conn) signalIDChangedLocked() {
	close(c.idChanged)
	c.idChanged = make(chan struct{})
}

func (c *Conn) removeDefinitelyUnsent(p *pendingOperation) {
	c.mu.Lock()
	if c.pending[p.id] == p {
		delete(c.pending, p.id)
		p.terminal = true
		p.finishLifecycle()
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
		p.finishLifecycle()
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

func (p *pendingOperation) finishLifecycle() {
	p.lifecycleOnce.Do(func() { close(p.lifecycleDone) })
}

type responseStream struct {
	pending *pendingOperation
	once    sync.Once
}

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
	target.finishLifecycle()
	target.signalReady()
	c.mu.Unlock()

	_, err = c.writeAll(ctx, message)
	c.releaseWriter()
	c.releaseReserved(abandonID)
	if err != nil {
		c.retire(err)
	}
}

var (
	abandonRequestIdentifier = ber.Identifier{Class: ber.ClassApplication, Number: 16}
	unbindRequestIdentifier  = ber.Identifier{Class: ber.ClassApplication, Number: 2}
)

func encodeAbandonRequest(messageID, target MessageID) ([]byte, error) {
	protocol, err := ber.AppendIntegerWithIdentifier(nil, abandonRequestIdentifier, int64(target))
	if err != nil {
		return nil, err
	}
	return encodeInternalRequest(messageID, protocol)
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

	classification := p.pattern.Classify(response.ProtocolID)
	if classification == ClassificationInvalid {
		c.mu.Unlock()
		return &ProtocolError{Kind: ProtocolUnexpectedIdentifier, MessageID: response.MessageID, Got: response.ProtocolID}
	}
	if classification == ClassificationComplete {
		delete(c.pending, p.id)
		p.terminal = true
		p.finishLifecycle()
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
	if response.ProtocolID != extendedResponseIdentifier {
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

var (
	extendedResponseIdentifier = ber.Identifier{Class: ber.ClassApplication, Constructed: true, Number: 24}
	referralIdentifier         = ber.Identifier{Class: ber.ClassContextSpecific, Constructed: true, Number: 3}
	responseNameIdentifier     = ber.Identifier{Class: ber.ClassContextSpecific, Number: 10}
	responseValueIdentifier    = ber.Identifier{Class: ber.ClassContextSpecific, Number: 11}
	noticeOfDisconnectionOID   = []byte("1.3.6.1.4.1.1466.20036")
)

func parseNotice(protocol []byte, limits ber.Limits) (*NoticeError, error) {
	r, err := ber.NewReader(protocol, limits)
	if err != nil {
		return nil, err
	}
	contents, err := r.Constructed(extendedResponseIdentifier)
	if err != nil {
		return nil, err
	}
	if err := r.RequireEmpty(); err != nil {
		return nil, err
	}
	resultCode, err := contents.Enumerated()
	if err != nil {
		return nil, err
	}
	if _, err := contents.OctetString(); err != nil {
		return nil, err
	}
	diagnostic, err := contents.OctetString()
	if err != nil {
		return nil, err
	}
	if !contents.Empty() {
		id, err := contents.PeekIdentifier()
		if err != nil {
			return nil, err
		}
		if id == referralIdentifier {
			referrals, err := contents.Constructed(referralIdentifier)
			if err != nil {
				return nil, err
			}
			if referrals.Empty() {
				return nil, errors.New("arden: unsolicited referral is empty")
			}
			for !referrals.Empty() {
				if _, err := referrals.OctetString(); err != nil {
					return nil, err
				}
			}
		}
	}
	var responseName []byte
	if !contents.Empty() {
		id, err := contents.PeekIdentifier()
		if err != nil {
			return nil, err
		}
		if id == responseNameIdentifier {
			responseName, err = contents.Primitive(responseNameIdentifier)
			if err != nil {
				return nil, err
			}
		}
	}
	if !contents.Empty() {
		id, err := contents.PeekIdentifier()
		if err != nil {
			return nil, err
		}
		if id == responseValueIdentifier {
			if _, err := contents.Primitive(responseValueIdentifier); err != nil {
				return nil, err
			}
		}
	}
	for !contents.Empty() {
		if _, err := contents.SkipElement(); err != nil {
			return nil, err
		}
	}
	if !bytes.Equal(responseName, noticeOfDisconnectionOID) {
		return nil, nil
	}
	return &NoticeError{ResultCode: resultCode, Diagnostic: slices.Clone(diagnostic)}, nil
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
	c.mu.Unlock()

	var closeErr error
	select {
	case <-c.writeToken:
		c.mu.Lock()
		id, ok := c.tryReserveMessageIDLocked()
		c.mu.Unlock()
		if ok {
			protocol, _ := ber.AppendPrimitive(nil, unbindRequestIdentifier, nil)
			message, _ := encodeInternalRequest(id, protocol)
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
		p.terminal = true
		p.finishLifecycle()
		p.signalReady()
	}
	clear(c.tombstones)
	c.signalIDChangedLocked()
	select {
	case c.unsolicitedReady <- struct{}{}:
	default:
	}
	c.mu.Unlock()
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
