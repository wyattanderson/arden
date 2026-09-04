package gssapi

import (
	"bytes"
	"context"
	"errors"
	"io"
	"slices"
	"sync"
	"testing"

	gogssapi "github.com/golang-auth/go-gssapi/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wyattanderson/arden"
	"github.com/wyattanderson/arden/auth"
	"github.com/wyattanderson/arden/ber"
	"github.com/wyattanderson/arden/rfc4511"
)

func TestAuthenticationOnlyGSSAPIExchange(t *testing.T) {
	securityContext := &fakeSecurityContext{
		continues: []continueResult{
			{
				output: []byte("client-context-one"),
				needed: true,
				info: gogssapi.SecContextInfoPartial{
					Flags: gogssapi.ContextFlagMutual | gogssapi.ContextFlagInteg,
					Mech:  gogssapi.GSS_MECH_KRB5,
				},
			},
			{
				output: []byte{},
				needed: false,
				info: gogssapi.SecContextInfoPartial{
					Flags:            gogssapi.ContextFlagMutual | gogssapi.ContextFlagInteg,
					Mech:             gogssapi.GSS_MECH_KRB5,
					FullyEstablished: true,
				},
			},
		},
		unwrapInput:   []byte("wrapped-server-offer"),
		unwrapped:     []byte{layerNone, 0, 0, 0},
		wrappedOutput: []byte("wrapped-client-selection"),
	}
	provider := &fakeProvider{name: new(fakeName), securityContext: securityContext}
	authentication := newTestAuthentication(t, provider, WithAuthorizationID("dn:uid=delegate,dc=example"))
	session := &scriptedSession{responses: []arden.Response{
		bindResponse(t, rfc4511.ResultSASLBindInProgress, true, []byte("server-context-one"), nil),
		bindResponse(t, rfc4511.ResultSASLBindInProgress, true, []byte("wrapped-server-offer"), nil),
		bindResponse(t, rfc4511.ResultSuccess, false, nil, nil),
	}}

	authenticatorValue, err := authentication.Begin(context.Background(), tlsEndpoint())
	require.NoError(t, err)
	identity, err := authenticatorValue.Authenticate(context.Background(), session)
	require.NoError(t, err)
	require.Equal(t, "kerberos-principal-a", identity.StableID)
	require.Equal(t, "ldap@ipa.example.test", provider.importedName)
	require.Equal(t, gogssapi.GSS_NT_HOSTBASED_SERVICE.OidString(), provider.importedType)
	require.NotNil(t, provider.initOptions.Mech)
	require.Equal(t, gogssapi.GSS_MECH_KRB5.OidString(), provider.initOptions.Mech.OidString())
	wantFlags := gogssapi.ContextFlagMutual | gogssapi.ContextFlagInteg
	require.Equal(t, wantFlags, provider.initOptions.Flags)
	require.True(t, slices.EqualFunc(securityContext.continueInputs, [][]byte{nil, []byte("server-context-one")}, bytes.Equal))
	require.Equal(t, []byte("wrapped-server-offer"), securityContext.unwrapSeen)
	wantSelection := append([]byte{layerNone, 0, 0, 0}, []byte("dn:uid=delegate,dc=example")...)
	require.Equal(t, wantSelection, securityContext.wrapSeen)
	require.False(t, securityContext.wrapConfidential)
	require.Zero(t, securityContext.wrapQoP)

	wantTokens := [][]byte{
		[]byte("client-context-one"),
		{},
		[]byte("wrapped-client-selection"),
	}
	require.Len(t, session.operations, len(wantTokens))
	for i, operation := range session.operations {
		request, ok := operation.Protocol.(*rfc4511.BindRequest)
		require.True(t, ok)
		sasl, ok := request.Authentication.(rfc4511.SASLAuthentication)
		require.True(t, ok)
		assert.Equal(t, "GSSAPI", string(sasl.Mechanism))
		assert.True(t, sasl.HasCredentials)
		assert.Equal(t, wantTokens[i], sasl.Credentials)
		assert.Empty(t, request.Name)
		assert.Equal(t, "ldap.bind", operation.Metadata.Label)
	}

	require.NoError(t, authenticatorValue.Close())
	require.NoError(t, authenticatorValue.Close())
	assert.Equal(t, 1, provider.name.releases)
	assert.Equal(t, 1, securityContext.deletes)
	assert.Equal(t, 1, provider.releases)
}

func TestGSSAPIRejectsPlaintextBeforeCreatingProvider(t *testing.T) {
	providerCalls := 0
	authentication, err := NewWithProviderFactory("identity", func() (gogssapi.Provider, error) {
		providerCalls++
		return &fakeProvider{}, nil
	})
	require.NoError(t, err)
	endpoint := arden.Endpoint{ID: "plain", Address: "ipa.example.test:389", Transport: arden.TransportPlaintext}
	require.Error(t, authentication.ValidateEndpoint(endpoint))
	_, err = authentication.Begin(context.Background(), endpoint)
	require.Error(t, err)
	assert.Zero(t, providerCalls)
}

func TestGSSAPIReplacementConversationUsesNewProviderAndStableIdentity(t *testing.T) {
	var providers []*fakeProvider
	authentication, err := NewWithProviderFactory("pool-partition-a", func() (gogssapi.Provider, error) {
		provider := &fakeProvider{
			name:            new(fakeName),
			securityContext: completedFakeContext([]byte{layerNone, 0, 0, 0}),
		}
		providers = append(providers, provider)
		return provider, nil
	})
	require.NoError(t, err)

	for range 2 {
		authenticator, err := authentication.Begin(context.Background(), tlsEndpoint())
		require.NoError(t, err)
		session := &scriptedSession{responses: []arden.Response{
			bindResponse(t, rfc4511.ResultSASLBindInProgress, true, []byte("offer"), nil),
			bindResponse(t, rfc4511.ResultSuccess, false, nil, nil),
		}}
		identity, err := authenticator.Authenticate(context.Background(), session)
		require.NoError(t, err)
		require.Equal(t, "pool-partition-a", identity.StableID)
		require.NoError(t, authenticator.Close())
	}

	require.Len(t, providers, 2)
	require.NotSame(t, providers[0], providers[1])
	for _, provider := range providers {
		assert.Equal(t, 1, provider.releases)
		assert.Equal(t, 1, provider.securityContext.deletes)
	}
}

func TestGSSAPIRejectsSASLDataLayers(t *testing.T) {
	tests := []struct {
		name         string
		offer        []byte
		confidential bool
		failure      NegotiationFailure
	}{
		{name: "integrity only", offer: []byte{layerIntegrity, 0, 0, 1}, failure: FailureNoAuthenticationOnlyLayer},
		{name: "confidentiality only", offer: []byte{layerConfidentiality, 0, 0, 1}, failure: FailureNoAuthenticationOnlyLayer},
		{name: "short offer", offer: []byte{layerNone, 0, 0}, failure: FailureInvalidSecurityOffer},
		{name: "encrypted offer", offer: []byte{layerNone, 0, 0, 0}, confidential: true, failure: FailureEncryptedSecurityOffer},
		{name: "authentication only with buffer", offer: []byte{layerNone, 0, 0, 1}, failure: FailureInvalidServerBuffer},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			securityContext := completedFakeContext(test.offer)
			securityContext.unwrapConfidential = test.confidential
			provider := &fakeProvider{name: new(fakeName), securityContext: securityContext}
			authentication := newTestAuthentication(t, provider)
			session := &scriptedSession{responses: []arden.Response{
				bindResponse(t, rfc4511.ResultSASLBindInProgress, true, []byte("offer"), nil),
			}}
			authenticator, err := authentication.Begin(context.Background(), tlsEndpoint())
			require.NoError(t, err)
			_, err = authenticator.Authenticate(context.Background(), session)
			var negotiationErr *NegotiationError
			require.ErrorAs(t, err, &negotiationErr)
			assert.Equal(t, test.failure, negotiationErr.Failure)
			require.ErrorIs(t, err, ErrNegotiation)
			assert.Empty(t, securityContext.wrapSeen)
			assert.Len(t, session.operations, 1)
			assert.NoError(t, authenticator.Close())
		})
	}
}

func TestGSSAPICancellationStopsBetweenNativeRounds(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	securityContext := &fakeSecurityContext{continues: []continueResult{
		{
			output: []byte("client-one"),
			needed: true,
			info: gogssapi.SecContextInfoPartial{
				Flags: gogssapi.ContextFlagMutual | gogssapi.ContextFlagInteg,
				Mech:  gogssapi.GSS_MECH_KRB5,
			},
		},
		{
			output: []byte("must-not-run"),
			needed: false,
			info: gogssapi.SecContextInfoPartial{
				Flags:            gogssapi.ContextFlagMutual | gogssapi.ContextFlagInteg,
				Mech:             gogssapi.GSS_MECH_KRB5,
				FullyEstablished: true,
			},
		},
	}}
	provider := &fakeProvider{name: new(fakeName), securityContext: securityContext}
	authentication := newTestAuthentication(t, provider)
	session := &scriptedSession{
		responses: []arden.Response{bindResponse(t, rfc4511.ResultSASLBindInProgress, true, []byte("server-one"), nil)},
		afterResponse: func(int) {
			cancel()
		},
	}
	authenticator, err := authentication.Begin(ctx, tlsEndpoint())
	require.NoError(t, err)
	_, err = authenticator.Authenticate(ctx, session)
	require.ErrorIs(t, err, context.Canceled)
	assert.Len(t, securityContext.continueInputs, 1)
	assert.Len(t, session.operations, 1)
	assert.NoError(t, authenticator.Close())
}

func TestGSSErrorPreservesMajorAndTypedCauseWithoutUnsafeText(t *testing.T) {
	const secret = "credential cache /secret/path for principal secret@EXAMPLE.TEST"
	providerCause := gogssapi.FatalStatus{
		FatalErrorCode: gogssapi.FatalErrorCode(11),
		MechErrors:     []error{errors.New(secret)},
	}
	securityContext := &fakeSecurityContext{continues: []continueResult{{err: providerCause}}}
	provider := &fakeProvider{name: new(fakeName), securityContext: securityContext}
	authentication := newTestAuthentication(t, provider)
	authenticator, err := authentication.Begin(context.Background(), tlsEndpoint())
	require.NoError(t, err)
	_, err = authenticator.Authenticate(context.Background(), &scriptedSession{})
	var gssErr *Error
	require.ErrorAs(t, err, &gssErr)
	assert.Equal(t, OperationContinue, gssErr.Operation)
	assert.True(t, gssErr.MajorKnown)
	assert.Equal(t, uint32(11<<16), gssErr.Major)
	require.ErrorIs(t, err, gogssapi.ErrCredentialsExpired)
	assert.NotContains(t, err.Error(), secret)
	assert.NoError(t, authenticator.Close())
}

func TestProviderFailureAndPartialSetupReleaseHandlesOnce(t *testing.T) {
	t.Run("unavailable provider", func(t *testing.T) {
		const secret = "native loader included /secret/provider/path"
		authentication, err := NewWithProviderFactory("identity", func() (gogssapi.Provider, error) {
			return nil, errors.New(secret)
		})
		require.NoError(t, err)
		_, err = authentication.Begin(context.Background(), tlsEndpoint())
		var gssErr *Error
		require.ErrorAs(t, err, &gssErr)
		assert.Equal(t, OperationNewProvider, gssErr.Operation)
		assert.NotContains(t, err.Error(), secret)
	})

	t.Run("context initialization failure", func(t *testing.T) {
		provider := &fakeProvider{name: new(fakeName), initErr: errors.New("init failed")}
		authentication := newTestAuthentication(t, provider)
		authenticator, err := authentication.Begin(context.Background(), tlsEndpoint())
		require.NoError(t, err)
		_, err = authenticator.Authenticate(context.Background(), &scriptedSession{})
		var gssErr *Error
		require.ErrorAs(t, err, &gssErr)
		assert.Equal(t, OperationInitContext, gssErr.Operation)
		require.NoError(t, authenticator.Close())
		require.NoError(t, authenticator.Close())
		assert.Equal(t, 1, provider.name.releases)
		assert.Equal(t, 1, provider.releases)
	})
}

func TestGSSAPIContextRoundLimitAndBindFailure(t *testing.T) {
	t.Run("round limit", func(t *testing.T) {
		securityContext := &fakeSecurityContext{continues: []continueResult{
			{output: []byte("one"), needed: true, info: partialContextInfo()},
			{output: []byte("two"), needed: true, info: partialContextInfo()},
		}}
		provider := &fakeProvider{name: new(fakeName), securityContext: securityContext}
		authentication := newTestAuthentication(t, provider, WithMaxContextRounds(2))
		session := &scriptedSession{responses: []arden.Response{
			bindResponse(t, rfc4511.ResultSASLBindInProgress, true, []byte("server-one"), nil),
			bindResponse(t, rfc4511.ResultSASLBindInProgress, true, []byte("server-two"), nil),
		}}
		authenticator, err := authentication.Begin(context.Background(), tlsEndpoint())
		require.NoError(t, err)
		_, err = authenticator.Authenticate(context.Background(), session)
		var negotiationErr *NegotiationError
		require.ErrorAs(t, err, &negotiationErr)
		assert.Equal(t, FailureTooManyRounds, negotiationErr.Failure)
		assert.NoError(t, authenticator.Close())
	})

	t.Run("server rejection", func(t *testing.T) {
		const secret = "server diagnostic containing a token"
		securityContext := completedFakeContext([]byte{layerNone, 0, 0, 0})
		provider := &fakeProvider{name: new(fakeName), securityContext: securityContext}
		authentication := newTestAuthentication(t, provider)
		session := &scriptedSession{responses: []arden.Response{
			bindResponse(t, rfc4511.ResultInvalidCredentials, false, nil, []byte(secret)),
		}}
		authenticator, err := authentication.Begin(context.Background(), tlsEndpoint())
		require.NoError(t, err)
		_, err = authenticator.Authenticate(context.Background(), session)
		var bindErr *auth.BindError
		require.ErrorAs(t, err, &bindErr)
		assert.Equal(t, rfc4511.ResultInvalidCredentials, bindErr.ResultCode)
		assert.NotContains(t, err.Error(), secret)
		assert.NoError(t, authenticator.Close())
	})
}

func TestGSSAPIConfigurationValidation(t *testing.T) {
	factory := func() (gogssapi.Provider, error) { return &fakeProvider{}, nil }
	_, err := NewWithProviderFactory("", factory)
	require.Error(t, err)
	_, err = NewWithProviderFactory("identity", nil)
	require.Error(t, err)
	_, err = NewWithProviderFactory("identity", factory, nil)
	require.Error(t, err)
	_, err = NewWithProviderFactory("identity", factory, WithMaxContextRounds(0))
	require.Error(t, err)
	_, err = NewWithProviderFactory("identity", factory, WithAuthorizationID(string([]byte{0xff})))
	require.Error(t, err)
	_, err = NewWithProviderFactory("identity", factory, WithAuthorizationID("dn:user\x00suffix"))
	assert.Error(t, err)
}

func newTestAuthentication(t *testing.T, provider *fakeProvider, options ...Option) *Authentication {
	t.Helper()
	authentication, err := NewWithProviderFactory("kerberos-principal-a", func() (gogssapi.Provider, error) {
		return provider, nil
	}, options...)
	require.NoError(t, err)
	return authentication
}

func tlsEndpoint() arden.Endpoint {
	return arden.Endpoint{
		ID:         "freeipa",
		Address:    "ipa.example.test:636",
		ServerName: "ipa.example.test",
	}
}

func partialContextInfo() gogssapi.SecContextInfoPartial {
	return gogssapi.SecContextInfoPartial{
		Flags: gogssapi.ContextFlagMutual | gogssapi.ContextFlagInteg,
		Mech:  gogssapi.GSS_MECH_KRB5,
	}
}

func completedFakeContext(offer []byte) *fakeSecurityContext {
	return &fakeSecurityContext{
		continues: []continueResult{{
			output: []byte("client-context"),
			info: gogssapi.SecContextInfoPartial{
				Flags:            gogssapi.ContextFlagMutual | gogssapi.ContextFlagInteg,
				Mech:             gogssapi.GSS_MECH_KRB5,
				FullyEstablished: true,
			},
		}},
		unwrapInput:   []byte("offer"),
		unwrapped:     bytes.Clone(offer),
		wrappedOutput: []byte("selection"),
	}
}

type fakeProvider struct {
	gogssapi.Provider

	name            *fakeName
	securityContext *fakeSecurityContext
	initErr         error
	releaseErr      error
	importedName    string
	importedType    string
	initOptions     gogssapi.InitSecContextOptions
	releases        int
}

func (p *fakeProvider) ImportName(name string, nameType gogssapi.GssNameType) (gogssapi.GssName, error) {
	p.importedName = name
	p.importedType = nameType.OidString()
	if p.name == nil {
		p.name = new(fakeName)
	}
	return p.name, nil
}

func (p *fakeProvider) InitSecContext(_ gogssapi.GssName, options ...gogssapi.InitSecContextOption) (gogssapi.SecContext, error) {
	p.initOptions = gogssapi.InitSecContextOptions{}
	for _, option := range options {
		option(&p.initOptions)
	}
	if p.initErr != nil {
		return p.securityContext, p.initErr
	}
	return p.securityContext, nil
}

func (p *fakeProvider) Release() error {
	p.releases++
	return p.releaseErr
}

type fakeName struct {
	gogssapi.GssName
	releases int
}

func (n *fakeName) Release() error {
	n.releases++
	return nil
}

type continueResult struct {
	output []byte
	info   gogssapi.SecContextInfoPartial
	needed bool
	err    error
}

type fakeSecurityContext struct {
	gogssapi.SecContext
	mu sync.Mutex

	continues          []continueResult
	continueInputs     [][]byte
	continueNeeded     bool
	unwrapInput        []byte
	unwrapped          []byte
	unwrapSeen         []byte
	unwrapConfidential bool
	unwrapQoP          gogssapi.QoP
	unwrapErr          error
	wrappedOutput      []byte
	wrapSeen           []byte
	wrapConfidential   bool
	wrapQoP            gogssapi.QoP
	wrapErr            error
	deletes            int
	deleteErr          error
}

func (c *fakeSecurityContext) Continue(token []byte) ([]byte, gogssapi.SecContextInfoPartial, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.continueInputs = append(c.continueInputs, bytes.Clone(token))
	index := len(c.continueInputs) - 1
	if index >= len(c.continues) {
		return nil, gogssapi.SecContextInfoPartial{}, errors.New("unexpected Continue call")
	}
	result := c.continues[index]
	c.continueNeeded = result.needed
	return bytes.Clone(result.output), result.info, result.err
}

func (c *fakeSecurityContext) ContinueNeeded() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.continueNeeded
}

func (c *fakeSecurityContext) Unwrap(token []byte) ([]byte, bool, gogssapi.QoP, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.unwrapSeen = bytes.Clone(token)
	if c.unwrapInput != nil && !bytes.Equal(token, c.unwrapInput) {
		return nil, false, 0, errors.New("unexpected Unwrap input")
	}
	return bytes.Clone(c.unwrapped), c.unwrapConfidential, c.unwrapQoP, c.unwrapErr
}

func (c *fakeSecurityContext) Wrap(message []byte, confidential bool, qop gogssapi.QoP) ([]byte, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.wrapSeen = bytes.Clone(message)
	c.wrapConfidential = confidential
	c.wrapQoP = qop
	return bytes.Clone(c.wrappedOutput), confidential, c.wrapErr
}

func (c *fakeSecurityContext) Delete() ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deletes++
	return []byte("delete-token"), c.deleteErr
}

type scriptedSession struct {
	responses     []arden.Response
	operations    []arden.Operation[rfc4511.BindResponse]
	afterResponse func(int)
}

func (s *scriptedSession) Do(ctx context.Context, operation arden.AnyOperation) (arden.ResponseStream, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	index := len(s.operations)
	if index >= len(s.responses) {
		return nil, errors.New("unexpected Bind operation")
	}
	typed, ok := operation.(arden.Operation[rfc4511.BindResponse])
	if !ok {
		return nil, errors.New("unexpected non-Bind operation")
	}
	s.operations = append(s.operations, cloneBindOperation(typed))
	return &scriptedStream{response: s.responses[index], index: index, afterResponse: s.afterResponse}, nil
}

func cloneBindOperation(operation arden.Operation[rfc4511.BindResponse]) arden.Operation[rfc4511.BindResponse] {
	request, ok := operation.Protocol.(*rfc4511.BindRequest)
	if !ok {
		return operation
	}
	clone := *request
	if sasl, ok := request.Authentication.(rfc4511.SASLAuthentication); ok {
		sasl.Credentials = bytes.Clone(sasl.Credentials)
		clone.Authentication = sasl
	}
	operation.Protocol = &clone
	return operation
}

type scriptedStream struct {
	response      arden.Response
	index         int
	afterResponse func(int)
	read          bool
}

func (s *scriptedStream) Next(context.Context) (arden.Response, error) {
	if s.read {
		return arden.Response{}, io.EOF
	}
	s.read = true
	if s.afterResponse != nil {
		s.afterResponse(s.index)
	}
	return s.response, nil
}

func (*scriptedStream) Close() error { return nil }

func bindResponse(t *testing.T, code rfc4511.ResultCode, hasCredentials bool, credentials, diagnostic []byte) arden.Response {
	t.Helper()
	protocol, err := (rfc4511.BindResponse{
		Result: rfc4511.LDAPResult{
			ResultCode:        code,
			DiagnosticMessage: rfc4511.LDAPString(string(diagnostic)),
		},
		HasServerSASLCredentials: hasCredentials,
		ServerSASLCredentials:    bytes.Clone(credentials),
	}).AppendBER(nil)
	require.NoError(t, err)
	message, err := ber.Sequence().
		Add(ber.Integer(1)).
		Add(ber.Encoded(protocol)).
		AppendBER(nil)
	require.NoError(t, err)
	response, err := arden.ParseResponse(message, ber.DefaultLimits())
	require.NoError(t, err)
	return response
}
