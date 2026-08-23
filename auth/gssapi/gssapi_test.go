package gssapi

import (
	"bytes"
	"context"
	"errors"
	"io"
	"slices"
	"strings"
	"sync"
	"testing"

	gogssapi "github.com/golang-auth/go-gssapi/v3"

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
	if err != nil {
		t.Fatal(err)
	}
	identity, err := authenticatorValue.Authenticate(context.Background(), session)
	if err != nil {
		t.Fatal(err)
	}
	if identity.StableID != "kerberos-principal-a" {
		t.Fatalf("identity = %#v", identity)
	}
	if provider.importedName != "ldap@ipa.example.test" || provider.importedType != gogssapi.GSS_NT_HOSTBASED_SERVICE.OidString() {
		t.Fatalf("imported target = %q, %q", provider.importedName, provider.importedType)
	}
	if provider.initOptions.Mech == nil || provider.initOptions.Mech.OidString() != gogssapi.GSS_MECH_KRB5.OidString() {
		t.Fatalf("requested mechanism = %#v", provider.initOptions.Mech)
	}
	wantFlags := gogssapi.ContextFlagMutual | gogssapi.ContextFlagInteg
	if provider.initOptions.Flags != wantFlags {
		t.Fatalf("requested flags = %v, want %v", provider.initOptions.Flags, wantFlags)
	}
	if got, want := securityContext.continueInputs, [][]byte{nil, []byte("server-context-one")}; !slices.EqualFunc(got, want, bytes.Equal) {
		t.Fatalf("context inputs = %q, want %q", got, want)
	}
	if !bytes.Equal(securityContext.unwrapSeen, []byte("wrapped-server-offer")) {
		t.Fatalf("Unwrap input = %q", securityContext.unwrapSeen)
	}
	wantSelection := append([]byte{layerNone, 0, 0, 0}, []byte("dn:uid=delegate,dc=example")...)
	if !bytes.Equal(securityContext.wrapSeen, wantSelection) || securityContext.wrapConfidential || securityContext.wrapQoP != 0 {
		t.Fatalf("Wrap = %x, confidential=%t, qop=%d", securityContext.wrapSeen, securityContext.wrapConfidential, securityContext.wrapQoP)
	}

	wantTokens := [][]byte{
		[]byte("client-context-one"),
		{},
		[]byte("wrapped-client-selection"),
	}
	if len(session.operations) != len(wantTokens) {
		t.Fatalf("Bind operations = %d, want %d", len(session.operations), len(wantTokens))
	}
	for i, operation := range session.operations {
		request, ok := operation.Protocol.(*rfc4511.BindRequest)
		if !ok {
			t.Fatalf("operation %d protocol = %T", i, operation.Protocol)
		}
		sasl, ok := request.Authentication.(rfc4511.SASLAuthentication)
		if !ok || string(sasl.Mechanism) != "GSSAPI" || !sasl.HasCredentials || !bytes.Equal(sasl.Credentials, wantTokens[i]) {
			t.Fatalf("operation %d SASL = %#v", i, request.Authentication)
		}
		if len(request.Name) != 0 || operation.Metadata.Label != "ldap.bind" {
			t.Fatalf("operation %d Bind metadata = %#v, name=%q", i, operation.Metadata, request.Name)
		}
	}

	if err := authenticatorValue.Close(); err != nil {
		t.Fatal(err)
	}
	if err := authenticatorValue.Close(); err != nil {
		t.Fatal(err)
	}
	if provider.name.releases != 1 || securityContext.deletes != 1 || provider.releases != 1 {
		t.Fatalf("release counts: name=%d context=%d provider=%d", provider.name.releases, securityContext.deletes, provider.releases)
	}
}

func TestGSSAPIRejectsPlaintextBeforeCreatingProvider(t *testing.T) {
	providerCalls := 0
	authentication, err := NewWithProviderFactory("identity", func() (gogssapi.Provider, error) {
		providerCalls++
		return &fakeProvider{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	endpoint := arden.Endpoint{ID: "plain", Address: "ipa.example.test:389", Transport: arden.TransportPlaintext}
	if err := authentication.ValidateEndpoint(endpoint); err == nil {
		t.Fatal("ValidateEndpoint accepted plaintext")
	}
	if _, err := authentication.Begin(context.Background(), endpoint); err == nil {
		t.Fatal("Begin accepted plaintext")
	}
	if providerCalls != 0 {
		t.Fatalf("provider factory calls = %d, want 0", providerCalls)
	}
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
	if err != nil {
		t.Fatal(err)
	}

	for i := range 2 {
		authenticator, err := authentication.Begin(context.Background(), tlsEndpoint())
		if err != nil {
			t.Fatal(err)
		}
		session := &scriptedSession{responses: []arden.Response{
			bindResponse(t, rfc4511.ResultSASLBindInProgress, true, []byte("offer"), nil),
			bindResponse(t, rfc4511.ResultSuccess, false, nil, nil),
		}}
		identity, err := authenticator.Authenticate(context.Background(), session)
		if err != nil {
			t.Fatal(err)
		}
		if identity.StableID != "pool-partition-a" {
			t.Fatalf("conversation %d identity = %#v", i, identity)
		}
		if err := authenticator.Close(); err != nil {
			t.Fatal(err)
		}
	}

	if len(providers) != 2 || providers[0] == providers[1] {
		t.Fatalf("providers = %#v, want two distinct instances", providers)
	}
	for i, provider := range providers {
		if provider.releases != 1 || provider.securityContext.deletes != 1 {
			t.Fatalf("provider %d cleanup: provider=%d context=%d", i, provider.releases, provider.securityContext.deletes)
		}
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
			if err != nil {
				t.Fatal(err)
			}
			_, err = authenticator.Authenticate(context.Background(), session)
			var negotiationErr *NegotiationError
			if !errors.As(err, &negotiationErr) || negotiationErr.Failure != test.failure || !errors.Is(err, ErrNegotiation) {
				t.Fatalf("error = %#v, want failure %v", err, test.failure)
			}
			if len(securityContext.wrapSeen) != 0 || len(session.operations) != 1 {
				t.Fatalf("invalid offer advanced exchange: wrap=%x operations=%d", securityContext.wrapSeen, len(session.operations))
			}
			if err := authenticator.Close(); err != nil {
				t.Fatal(err)
			}
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
	if err != nil {
		t.Fatal(err)
	}
	_, err = authenticator.Authenticate(ctx, session)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context cancellation", err)
	}
	if len(securityContext.continueInputs) != 1 || len(session.operations) != 1 {
		t.Fatalf("cancellation advanced exchange: continues=%d operations=%d", len(securityContext.continueInputs), len(session.operations))
	}
	if err := authenticator.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestGSSErrorPreservesMajorAndTypedCauseWithoutUnsafeText(t *testing.T) {
	const secret = "credential cache /secret/path for principal secret@EXAMPLE.TEST"
	providerCause := gogssapi.FatalStatus{
		FatalErrorCode: gogssapi.FatalErrorCode(11),
		InfoStatus: gogssapi.InfoStatus{
			MechErrors: []error{errors.New(secret)},
		},
	}
	securityContext := &fakeSecurityContext{continues: []continueResult{{err: providerCause}}}
	provider := &fakeProvider{name: new(fakeName), securityContext: securityContext}
	authentication := newTestAuthentication(t, provider)
	authenticator, err := authentication.Begin(context.Background(), tlsEndpoint())
	if err != nil {
		t.Fatal(err)
	}
	_, err = authenticator.Authenticate(context.Background(), &scriptedSession{})
	var gssErr *Error
	if !errors.As(err, &gssErr) || gssErr.Operation != OperationContinue || !gssErr.MajorKnown || gssErr.Major != 11<<16 {
		t.Fatalf("GSS error = %#v", err)
	}
	if !errors.Is(err, gogssapi.ErrCredentialsExpired) {
		t.Fatalf("GSS error lost typed cause: %v", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("safe error leaked provider text: %v", err)
	}
	if err := authenticator.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestProviderFailureAndPartialSetupReleaseHandlesOnce(t *testing.T) {
	t.Run("unavailable provider", func(t *testing.T) {
		const secret = "native loader included /secret/provider/path"
		authentication, err := NewWithProviderFactory("identity", func() (gogssapi.Provider, error) {
			return nil, errors.New(secret)
		})
		if err != nil {
			t.Fatal(err)
		}
		_, err = authentication.Begin(context.Background(), tlsEndpoint())
		var gssErr *Error
		if !errors.As(err, &gssErr) || gssErr.Operation != OperationNewProvider || strings.Contains(err.Error(), secret) {
			t.Fatalf("provider error = %#v", err)
		}
	})

	t.Run("context initialization failure", func(t *testing.T) {
		provider := &fakeProvider{name: new(fakeName), initErr: errors.New("init failed")}
		authentication := newTestAuthentication(t, provider)
		authenticator, err := authentication.Begin(context.Background(), tlsEndpoint())
		if err != nil {
			t.Fatal(err)
		}
		_, err = authenticator.Authenticate(context.Background(), &scriptedSession{})
		var gssErr *Error
		if !errors.As(err, &gssErr) || gssErr.Operation != OperationInitContext {
			t.Fatalf("initialization error = %#v", err)
		}
		if err := authenticator.Close(); err != nil {
			t.Fatal(err)
		}
		if err := authenticator.Close(); err != nil {
			t.Fatal(err)
		}
		if provider.name.releases != 1 || provider.releases != 1 {
			t.Fatalf("release counts: name=%d provider=%d", provider.name.releases, provider.releases)
		}
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
		if err != nil {
			t.Fatal(err)
		}
		_, err = authenticator.Authenticate(context.Background(), session)
		var negotiationErr *NegotiationError
		if !errors.As(err, &negotiationErr) || negotiationErr.Failure != FailureTooManyRounds {
			t.Fatalf("round-limit error = %#v", err)
		}
		if err := authenticator.Close(); err != nil {
			t.Fatal(err)
		}
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
		if err != nil {
			t.Fatal(err)
		}
		_, err = authenticator.Authenticate(context.Background(), session)
		var bindErr *auth.BindError
		if !errors.As(err, &bindErr) || bindErr.ResultCode != rfc4511.ResultInvalidCredentials {
			t.Fatalf("Bind error = %#v", err)
		}
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("Bind error leaked diagnostic: %v", err)
		}
		if err := authenticator.Close(); err != nil {
			t.Fatal(err)
		}
	})
}

func TestGSSAPIConfigurationValidation(t *testing.T) {
	factory := func() (gogssapi.Provider, error) { return &fakeProvider{}, nil }
	if _, err := NewWithProviderFactory("", factory); err == nil {
		t.Fatal("accepted empty stable identity")
	}
	if _, err := NewWithProviderFactory("identity", nil); err == nil {
		t.Fatal("accepted nil provider factory")
	}
	if _, err := NewWithProviderFactory("identity", factory, nil); err == nil {
		t.Fatal("accepted nil option")
	}
	if _, err := NewWithProviderFactory("identity", factory, WithMaxContextRounds(0)); err == nil {
		t.Fatal("accepted zero round limit")
	}
	if _, err := NewWithProviderFactory("identity", factory, WithAuthorizationID(string([]byte{0xff}))); err == nil {
		t.Fatal("accepted invalid UTF-8 authorization identity")
	}
	if _, err := NewWithProviderFactory("identity", factory, WithAuthorizationID("dn:user\x00suffix")); err == nil {
		t.Fatal("accepted U+0000 authorization identity")
	}
}

func newTestAuthentication(t *testing.T, provider *fakeProvider, options ...Option) *Authentication {
	t.Helper()
	authentication, err := NewWithProviderFactory("kerberos-principal-a", func() (gogssapi.Provider, error) {
		return provider, nil
	}, options...)
	if err != nil {
		t.Fatal(err)
	}
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
	operations    []arden.Operation
	afterResponse func(int)
}

func (s *scriptedSession) Do(ctx context.Context, operation arden.Operation) (arden.ResponseStream, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	index := len(s.operations)
	if index >= len(s.responses) {
		return nil, errors.New("unexpected Bind operation")
	}
	s.operations = append(s.operations, cloneBindOperation(operation))
	return &scriptedStream{response: s.responses[index], index: index, afterResponse: s.afterResponse}, nil
}

func cloneBindOperation(operation arden.Operation) arden.Operation {
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
	if err != nil {
		t.Fatal(err)
	}
	contents, err := ber.AppendInteger(nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	contents = append(contents, protocol...)
	message, err := ber.AppendSequence(nil, contents)
	if err != nil {
		t.Fatal(err)
	}
	response, err := arden.ParseResponse(message, ber.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	return response
}
