package arden

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wyattanderson/arden/ber"
)

var testBindResponse = ber.Identifier{Class: ber.ClassApplication, Constructed: true, Number: 1}

type authenticationStub struct {
	begin func(context.Context, Endpoint) (Authenticator, error)
}

func (a authenticationStub) Begin(ctx context.Context, endpoint Endpoint) (Authenticator, error) {
	return a.begin(ctx, endpoint)
}

type authenticatorStub struct {
	authenticate func(context.Context, InitializationSession) (Identity, error)
	close        func() error
}

func (a *authenticatorStub) Authenticate(ctx context.Context, session InitializationSession) (Identity, error) {
	return a.authenticate(ctx, session)
}

func (a *authenticatorStub) Close() error {
	if a.close == nil {
		return nil
	}
	return a.close()
}

func newSetupPipeConnection(t *testing.T, options ConnectionOptions) (*Conn, net.Conn) {
	t.Helper()
	normalized, err := options.normalized()
	if err != nil {
		t.Fatal(err)
	}
	client, server := net.Pipe()
	conn, err := newConnWithState(client, Endpoint{
		ID: "setup", Address: "pipe", Transport: TransportPlaintext,
	}, normalized, MaxMessageID, stateTransportSetup)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		conn.retire(ErrClosed)
		_ = server.Close()
	})
	return conn, server
}

func bindLikeOperation(t *testing.T, token []byte) Operation {
	t.Helper()
	protocol, err := ber.AppendElement(nil, bindRequestIdentifier, token)
	if err != nil {
		t.Fatal(err)
	}
	pattern, err := NewResponsePattern(ResponseSpec{Complete: []ber.Identifier{testBindResponse}})
	if err != nil {
		t.Fatal(err)
	}
	return Operation{
		Protocol:     testProtocol{id: bindRequestIdentifier, encoded: protocol},
		Responses:    pattern,
		Cancellation: CancelClose,
	}
}

func performSetupRoundTrip(ctx context.Context, session InitializationSession, operation Operation) error {
	stream, err := session.Do(ctx, operation)
	if err != nil {
		return err
	}
	if _, err := stream.Next(ctx); err != nil {
		return err
	}
	_, err = stream.Next(ctx)
	if !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

func TestNoAuthenticationPublishesReadyConnectionWithoutBind(t *testing.T) {
	conn, _ := newSetupPipeConnection(t, ConnectionOptions{})
	identity, profile, err := new(Dialer).initialize(context.Background(), conn, nil)
	if err != nil {
		t.Fatal(err)
	}
	if profile != nil || identity.StableID != unauthenticatedIdentity {
		t.Fatalf("no-auth setup = %#v, %#v", identity, profile)
	}
	conn.mu.Lock()
	state := conn.state
	conn.mu.Unlock()
	if state != stateReady {
		t.Fatalf("connection state = %d, want ready", state)
	}
	if conn.Policy().Cancellation != CancellationConservative {
		t.Fatalf("default policy = %#v", conn.Policy())
	}
}

func TestAuthenticationAndInitializerAreExclusiveAndOrdered(t *testing.T) {
	conn, peer := newSetupPipeConnection(t, ConnectionOptions{})
	framer := newTestFramer(t, peer)
	peerErr := make(chan error, 1)
	go func() {
		first := readTestMessage(t, framer)
		if !bytes.Equal(first.Protocol, mustElement(t, bindRequestIdentifier, []byte("round-one"))) {
			peerErr <- errors.New("first setup request was not the authentication round")
			return
		}
		writeTestMessage(t, peer, testLDAPMessage(t, first.MessageID, testBindResponse, nil))
		second := readTestMessage(t, framer)
		if second.ProtocolID != testSearchRequest {
			peerErr <- errors.New("second setup request was not initialization")
			return
		}
		writeTestMessage(t, peer, testLDAPMessage(t, second.MessageID, testSearchDone, nil))
		peerErr <- nil
	}()

	var retained InitializationSession
	closed := false
	dialer := &Dialer{Authentication: authenticationStub{begin: func(context.Context, Endpoint) (Authenticator, error) {
		return &authenticatorStub{
			authenticate: func(ctx context.Context, session InitializationSession) (Identity, error) {
				if _, err := conn.Do(ctx, newTestOperation(t, testModifyRequest, ResponseSpec{NoResponse: true}, CancelNone)); !errors.Is(err, ErrConnectionNotReady) {
					return Identity{}, errors.New("application operation observed a pre-ready connection")
				}
				if err := performSetupRoundTrip(ctx, session, bindLikeOperation(t, []byte("round-one"))); err != nil {
					return Identity{}, err
				}
				return Identity{StableID: "principal-a"}, nil
			},
			close: func() error { closed = true; return nil },
		}, nil
	}}}
	initializer := func(ctx context.Context, session InitializationSession) (any, ConnectionPolicy, error) {
		retained = session
		op := newTestOperation(t, testSearchRequest, ResponseSpec{Complete: []ber.Identifier{testSearchDone}}, CancelDrain)
		if err := performSetupRoundTrip(ctx, session, op); err != nil {
			return nil, ConnectionPolicy{}, err
		}
		return "profile-a", ConnectionPolicy{Cancellation: CancellationRFC3909}, nil
	}

	identity, profile, err := dialer.initialize(context.Background(), conn, initializer)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-peerErr; err != nil {
		t.Fatal(err)
	}
	if !closed {
		t.Fatal("authenticator resources were not closed")
	}
	if identity.StableID != "principal-a" || profile != "profile-a" {
		t.Fatalf("setup handoff = %#v, %#v", identity, profile)
	}
	if conn.Identity() != identity || conn.Policy().Cancellation != CancellationRFC3909 {
		t.Fatalf("frozen connection setup = %#v, %#v", conn.Identity(), conn.Policy())
	}
	if _, err := retained.Do(context.Background(), newTestOperation(t, testModifyRequest, ResponseSpec{NoResponse: true}, CancelNone)); !errors.Is(err, ErrInitializationClosed) {
		t.Fatalf("retained initialization session error = %v", err)
	}
}

func TestMockSASLCanUseOpaqueMultiRoundBindTokens(t *testing.T) {
	conn, peer := newSetupPipeConnection(t, ConnectionOptions{})
	framer := newTestFramer(t, peer)
	tokens := [][]byte{{0x00, 0xff, 0x01}, {0x80, 0x00, 0x7f}}
	peerErr := make(chan error, 1)
	go func() {
		for _, token := range tokens {
			request := readTestMessage(t, framer)
			if !bytes.Equal(request.Protocol, mustElement(t, bindRequestIdentifier, token)) {
				peerErr <- errors.New("SASL token changed before framing")
				return
			}
			writeTestMessage(t, peer, testLDAPMessage(t, request.MessageID, testBindResponse, nil))
		}
		peerErr <- nil
	}()

	dialer := &Dialer{Authentication: authenticationStub{begin: func(context.Context, Endpoint) (Authenticator, error) {
		return &authenticatorStub{authenticate: func(ctx context.Context, session InitializationSession) (Identity, error) {
			for _, token := range tokens {
				if err := performSetupRoundTrip(ctx, session, bindLikeOperation(t, token)); err != nil {
					return Identity{}, err
				}
			}
			return Identity{StableID: "mock-sasl"}, nil
		}}, nil
	}}}
	if _, _, err := dialer.initialize(context.Background(), conn, nil); err != nil {
		t.Fatal(err)
	}
	if err := <-peerErr; err != nil {
		t.Fatal(err)
	}
}

func TestSetupContextCancellationStopsNextAuthenticationRound(t *testing.T) {
	conn, peer := newSetupPipeConnection(t, ConnectionOptions{})
	framer := newTestFramer(t, peer)
	firstRound := make(chan struct{})
	go func() {
		request := readTestMessage(t, framer)
		writeTestMessage(t, peer, testLDAPMessage(t, request.MessageID, testBindResponse, nil))
		close(firstRound)
	}()

	ctx, cancel := context.WithCancel(context.Background())
	dialer := &Dialer{Authentication: authenticationStub{begin: func(context.Context, Endpoint) (Authenticator, error) {
		return &authenticatorStub{authenticate: func(authCtx context.Context, session InitializationSession) (Identity, error) {
			if err := performSetupRoundTrip(authCtx, session, bindLikeOperation(t, []byte("one"))); err != nil {
				return Identity{}, err
			}
			<-firstRound
			cancel()
			_, err := session.Do(authCtx, bindLikeOperation(t, []byte("must-not-write")))
			return Identity{}, err
		}}, nil
	}}}
	_, _, err := dialer.initialize(ctx, conn, nil)
	if !errors.Is(err, context.Canceled) || !errors.Is(err, ErrSetup) {
		t.Fatalf("canceled authentication error = %v", err)
	}
	select {
	case <-conn.Done():
	default:
		t.Fatal("authentication failure left the connection usable")
	}
}

func TestInitializationTimeoutBudgetAndProfileMismatch(t *testing.T) {
	t.Run("failure", func(t *testing.T) {
		conn, _ := newSetupPipeConnection(t, ConnectionOptions{})
		sentinel := errors.New("initializer failed")
		initializer := func(context.Context, InitializationSession) (any, ConnectionPolicy, error) {
			return nil, ConnectionPolicy{}, sentinel
		}
		_, _, err := new(Dialer).initialize(context.Background(), conn, initializer)
		var setupErr *SetupError
		if !errors.As(err, &setupErr) || setupErr.Stage != SetupInitialization || !errors.Is(err, sentinel) {
			t.Fatalf("initializer failure = %v", err)
		}
		select {
		case <-conn.Done():
		default:
			t.Fatal("failed initializer left the connection usable")
		}
	})

	t.Run("timeout", func(t *testing.T) {
		conn, _ := newSetupPipeConnection(t, ConnectionOptions{InitializationTimeout: 20 * time.Millisecond})
		initializer := func(ctx context.Context, _ InitializationSession) (any, ConnectionPolicy, error) {
			<-ctx.Done()
			return nil, ConnectionPolicy{}, ctx.Err()
		}
		_, _, err := new(Dialer).initialize(context.Background(), conn, initializer)
		var setupErr *SetupError
		if !errors.As(err, &setupErr) || setupErr.Stage != SetupInitialization || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("initializer timeout = %v", err)
		}
	})

	t.Run("invalid policy", func(t *testing.T) {
		conn, _ := newSetupPipeConnection(t, ConnectionOptions{})
		initializer := func(context.Context, InitializationSession) (any, ConnectionPolicy, error) {
			return nil, ConnectionPolicy{}, nil
		}
		_, _, err := new(Dialer).initialize(context.Background(), conn, initializer)
		var setupErr *SetupError
		if !errors.As(err, &setupErr) || setupErr.Stage != SetupInitialization {
			t.Fatalf("invalid setup policy = %v", err)
		}
	})

	t.Run("operation budget", func(t *testing.T) {
		conn, peer := newSetupPipeConnection(t, ConnectionOptions{MaxInitializationOperations: 1})
		framer := newTestFramer(t, peer)
		go func() { _ = readTestMessage(t, framer) }()
		initializer := func(ctx context.Context, session InitializationSession) (any, ConnectionPolicy, error) {
			op := newTestOperation(t, testModifyRequest, ResponseSpec{NoResponse: true}, CancelNone)
			if _, err := session.Do(ctx, op); err != nil {
				return nil, ConnectionPolicy{}, err
			}
			_, err := session.Do(ctx, op)
			return nil, ConnectionPolicy{}, err
		}
		_, _, err := new(Dialer).initialize(context.Background(), conn, initializer)
		var limit *LimitError
		if !errors.As(err, &limit) || limit.Limit != "initialization operations" {
			t.Fatalf("initializer budget error = %v", err)
		}
	})

	t.Run("profile mismatch", func(t *testing.T) {
		conn, _ := newSetupPipeConnection(t, ConnectionOptions{})
		secret := errors.New("changed capabilities: sensitive-profile-value")
		initializer := func(context.Context, InitializationSession) (any, ConnectionPolicy, error) {
			return nil, ConnectionPolicy{}, &ProfileMismatchError{Err: secret}
		}
		_, _, err := new(Dialer).initialize(context.Background(), conn, initializer)
		var setupErr *SetupError
		if !errors.As(err, &setupErr) || setupErr.Stage != SetupProfileMismatch || !errors.Is(err, ErrProfileMismatch) {
			t.Fatalf("profile mismatch = %v", err)
		}
		if bytes.Contains([]byte(err.Error()), []byte("sensitive-profile-value")) {
			t.Fatalf("setup error leaked profile contents: %v", err)
		}
	})
}

func TestAuthenticationFailureClosesResourcesAndRedactsCause(t *testing.T) {
	conn, _ := newSetupPipeConnection(t, ConnectionOptions{})
	secretErr := errors.New("credential=should-never-be-logged")
	var closed atomic.Bool
	dialer := &Dialer{Authentication: authenticationStub{begin: func(context.Context, Endpoint) (Authenticator, error) {
		return &authenticatorStub{
			authenticate: func(context.Context, InitializationSession) (Identity, error) {
				return Identity{}, secretErr
			},
			close: func() error { closed.Store(true); return nil },
		}, nil
	}}}
	_, _, err := dialer.initialize(context.Background(), conn, nil)
	var setupErr *SetupError
	if !errors.As(err, &setupErr) || setupErr.Stage != SetupAuthentication || !errors.Is(err, secretErr) {
		t.Fatalf("authentication failure = %v", err)
	}
	if !closed.Load() {
		t.Fatal("failed authenticator was not closed")
	}
	if bytes.Contains([]byte(err.Error()), []byte("should-never-be-logged")) {
		t.Fatalf("setup error leaked authentication material: %v", err)
	}
	select {
	case <-conn.Done():
	default:
		t.Fatal("failed authentication connection was not closed")
	}
}

func TestBindCannotChangeAssociationAfterReady(t *testing.T) {
	conn, _ := newPipeConnection(t, ConnectionOptions{}, MaxMessageID)
	if _, err := conn.Do(context.Background(), bindLikeOperation(t, []byte("late-bind"))); !errors.Is(err, ErrAssociationChange) {
		t.Fatalf("application Bind error = %v", err)
	}
	unbind := newTestOperation(t, unbindRequestIdentifier, ResponseSpec{NoResponse: true}, CancelNone)
	if _, err := conn.Do(context.Background(), unbind); !errors.Is(err, ErrAssociationChange) {
		t.Fatalf("application Unbind error = %v", err)
	}
}

func TestInitializationOptionsAreBounded(t *testing.T) {
	defaults := DefaultConnectionOptions()
	if defaults.InitializationTimeout <= 0 || defaults.MaxInitializationOperations <= 0 {
		t.Fatalf("unbounded initialization defaults = %#v", defaults)
	}
	if err := (ConnectionOptions{InitializationTimeout: -time.Second}).Validate(); err == nil {
		t.Fatal("negative initialization timeout was accepted")
	}
	if err := (ConnectionOptions{MaxInitializationOperations: -1}).Validate(); err == nil {
		t.Fatal("negative initialization operation budget was accepted")
	}
}

func mustElement(t *testing.T, id ber.Identifier, value []byte) []byte {
	t.Helper()
	encoded, err := ber.AppendElement(nil, id, value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
