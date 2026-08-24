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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wyattanderson/arden/ber"
	"github.com/wyattanderson/arden/rfc4511"
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
	require.NoError(t, err)
	client, server := net.Pipe()
	conn, err := newConnWithState(client, Endpoint{
		ID: "setup", Address: "pipe", Transport: TransportPlaintext,
	}, normalized, MaxMessageID, stateTransportSetup)
	require.NoError(t, err)
	t.Cleanup(func() {
		conn.retire(ErrClosed)
		_ = server.Close()
	})
	return conn, server
}

func bindLikeOperation(t *testing.T, token []byte) Operation[rfc4511.BindResponse] {
	t.Helper()
	protocol, err := ber.AppendElement(nil, rfc4511.BindRequestIdentifier(), token)
	require.NoError(t, err)
	pattern, err := NewResponsePattern[rfc4511.BindResponse](ResponseSpec{Complete: []ber.Identifier{testBindResponse}})
	require.NoError(t, err)
	return Operation[rfc4511.BindResponse]{
		Protocol:     testProtocol{id: rfc4511.BindRequestIdentifier(), encoded: protocol},
		Responses:    pattern,
		Cancellation: CancelClose,
	}
}

func performSetupRoundTrip(ctx context.Context, session InitializationSession, operation AnyOperation) error {
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
	require.NoError(t, err)
	assert.Nil(t, profile)
	assert.Equal(t, unauthenticatedIdentity, identity.StableID)
	conn.mu.Lock()
	state := conn.state
	conn.mu.Unlock()
	assert.Equal(t, stateReady, state)
	assert.Equal(t, CancellationConservative, conn.Policy().Cancellation)
}

func TestAuthenticationAndInitializerAreExclusiveAndOrdered(t *testing.T) {
	conn, peer := newSetupPipeConnection(t, ConnectionOptions{})
	framer := newTestFramer(t, peer)
	peerErr := make(chan error, 1)
	go func() {
		first := readTestMessage(t, framer)
		if !bytes.Equal(first.Protocol, mustElement(t, rfc4511.BindRequestIdentifier(), []byte("round-one"))) {
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
	require.NoError(t, err)
	require.NoError(t, <-peerErr)
	assert.True(t, closed)
	assert.Equal(t, "principal-a", identity.StableID)
	assert.Equal(t, "profile-a", profile)
	assert.Equal(t, identity, conn.Identity())
	assert.Equal(t, CancellationRFC3909, conn.Policy().Cancellation)
	_, err = retained.Do(context.Background(), newTestOperation(t, testModifyRequest, ResponseSpec{NoResponse: true}, CancelNone))
	require.ErrorIs(t, err, ErrInitializationClosed)
}

func TestMockSASLCanUseOpaqueMultiRoundBindTokens(t *testing.T) {
	conn, peer := newSetupPipeConnection(t, ConnectionOptions{})
	framer := newTestFramer(t, peer)
	tokens := [][]byte{{0x00, 0xff, 0x01}, {0x80, 0x00, 0x7f}}
	peerErr := make(chan error, 1)
	go func() {
		for _, token := range tokens {
			request := readTestMessage(t, framer)
			if !bytes.Equal(request.Protocol, mustElement(t, rfc4511.BindRequestIdentifier(), token)) {
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
	_, _, err := dialer.initialize(context.Background(), conn, nil)
	require.NoError(t, err)
	assert.NoError(t, <-peerErr)
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
	require.ErrorIs(t, err, context.Canceled)
	require.ErrorIs(t, err, ErrSetup)
	select {
	case <-conn.Done():
	default:
		assert.Fail(t, "authentication failure left the connection usable")
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
		require.ErrorAs(t, err, &setupErr)
		assert.Equal(t, SetupInitialization, setupErr.Stage)
		require.ErrorIs(t, err, sentinel)
		select {
		case <-conn.Done():
		default:
			assert.Fail(t, "failed initializer left the connection usable")
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
		require.ErrorAs(t, err, &setupErr)
		assert.Equal(t, SetupInitialization, setupErr.Stage)
		require.ErrorIs(t, err, context.DeadlineExceeded)
	})

	t.Run("invalid policy", func(t *testing.T) {
		conn, _ := newSetupPipeConnection(t, ConnectionOptions{})
		initializer := func(context.Context, InitializationSession) (any, ConnectionPolicy, error) {
			return nil, ConnectionPolicy{}, nil
		}
		_, _, err := new(Dialer).initialize(context.Background(), conn, initializer)
		var setupErr *SetupError
		require.ErrorAs(t, err, &setupErr)
		assert.Equal(t, SetupInitialization, setupErr.Stage)
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
		require.ErrorAs(t, err, &limit)
		assert.Equal(t, "initialization operations", limit.Limit)
	})

	t.Run("profile mismatch", func(t *testing.T) {
		conn, _ := newSetupPipeConnection(t, ConnectionOptions{})
		secret := errors.New("changed capabilities: sensitive-profile-value")
		initializer := func(context.Context, InitializationSession) (any, ConnectionPolicy, error) {
			return nil, ConnectionPolicy{}, &ProfileMismatchError{Err: secret}
		}
		_, _, err := new(Dialer).initialize(context.Background(), conn, initializer)
		var setupErr *SetupError
		require.ErrorAs(t, err, &setupErr)
		assert.Equal(t, SetupProfileMismatch, setupErr.Stage)
		require.ErrorIs(t, err, ErrProfileMismatch)
		assert.NotContains(t, err.Error(), "sensitive-profile-value")
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
	require.ErrorAs(t, err, &setupErr)
	assert.Equal(t, SetupAuthentication, setupErr.Stage)
	require.ErrorIs(t, err, secretErr)
	assert.True(t, closed.Load())
	assert.NotContains(t, err.Error(), "should-never-be-logged")
	select {
	case <-conn.Done():
	default:
		assert.Fail(t, "failed authentication connection was not closed")
	}
}

func TestBindCannotChangeAssociationAfterReady(t *testing.T) {
	conn, _ := newPipeConnection(t, ConnectionOptions{}, MaxMessageID)
	_, err := conn.Do(context.Background(), bindLikeOperation(t, []byte("late-bind")))
	require.ErrorIs(t, err, ErrAssociationChange)
	unbind := newTestOperation(t, rfc4511.UnbindRequestIdentifier(), ResponseSpec{NoResponse: true}, CancelNone)
	_, err = conn.Do(context.Background(), unbind)
	require.ErrorIs(t, err, ErrAssociationChange)
}

func TestInitializationOptionsAreBounded(t *testing.T) {
	defaults := DefaultConnectionOptions()
	assert.Positive(t, defaults.InitializationTimeout)
	assert.Positive(t, defaults.MaxInitializationOperations)
	require.Error(t, (ConnectionOptions{InitializationTimeout: -time.Second}).Validate())
	assert.Error(t, (ConnectionOptions{MaxInitializationOperations: -1}).Validate())
}

func mustElement(t *testing.T, id ber.Identifier, value []byte) []byte {
	t.Helper()
	encoded, err := ber.AppendElement(nil, id, value)
	assert.NoError(t, err)
	return encoded
}
