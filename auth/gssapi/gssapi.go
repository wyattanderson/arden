package gssapi

import (
	"context"
	"errors"
	"reflect" //nolint:depguard // Authentication setup only: detect typed-nil handles from external GSS providers before calling their methods.
	"slices"
	"strings"
	"sync"
	"unicode/utf8"

	gogssapi "github.com/golang-auth/go-gssapi/v3"

	"github.com/wyattanderson/arden"
	"github.com/wyattanderson/arden/rfc4511"
)

const (
	defaultMaxContextRounds = 8
	ldapServiceName         = "ldap"
)

// ProviderFactory creates one independently owned GSS provider for each LDAP
// connection. The authenticator releases the provider on every outcome.
type ProviderFactory func() (gogssapi.Provider, error)

type options struct {
	authorizationID string
	maxRounds       int
}

// Option configures an RFC 4752 authentication mechanism.
type Option func(*options) error

// WithAuthorizationID requests an optional SASL authorization identity. The
// value must be valid UTF-8 and cannot contain U+0000. It is not used as the
// stable pool identity.
func WithAuthorizationID(id string) Option {
	return func(o *options) error {
		if !utf8.ValidString(id) {
			return errors.New("arden/auth/gssapi: authorization identity is not valid UTF-8")
		}
		if strings.IndexByte(id, 0) >= 0 {
			return errors.New("arden/auth/gssapi: authorization identity contains U+0000")
		}
		o.authorizationID = id
		return nil
	}
}

// WithMaxContextRounds changes the default bound on GSS context-establishment
// calls. The final RFC 4752 security-layer selection is not counted.
func WithMaxContextRounds(rounds int) Option {
	return func(o *options) error {
		if rounds <= 0 {
			return errors.New("arden/auth/gssapi: maximum context rounds must be positive")
		}
		o.maxRounds = rounds
		return nil
	}
}

// Authentication is reusable TLS-only GSSAPI configuration. It contains no
// credential or credential-cache handle; the native provider selects default
// initiator credentials independently for every connection.
type Authentication struct {
	identity        arden.Identity
	providerFactory ProviderFactory
	authorizationID string
	maxRounds       int
}

// NewWithProviderFactory constructs GSSAPI authentication around a provider
// adapter. Applications normally use auth/gssapi/native.New. stableID is
// nonsecret caller vocabulary used to partition profiles and pools.
func NewWithProviderFactory(stableID string, factory ProviderFactory, opts ...Option) (*Authentication, error) {
	identity := arden.Identity{StableID: stableID}
	if err := identity.Validate(); err != nil {
		return nil, err
	}
	if factory == nil {
		return nil, errors.New("arden/auth/gssapi: nil provider factory")
	}
	configuration := options{maxRounds: defaultMaxContextRounds}
	for _, option := range opts {
		if option == nil {
			return nil, errors.New("arden/auth/gssapi: nil option")
		}
		if err := option(&configuration); err != nil {
			return nil, err
		}
	}
	return &Authentication{
		identity:        identity,
		providerFactory: factory,
		authorizationID: configuration.authorizationID,
		maxRounds:       configuration.maxRounds,
	}, nil
}

// ValidateEndpoint rejects plaintext before Dialer opens a socket.
func (a *Authentication) ValidateEndpoint(endpoint arden.Endpoint) error {
	if endpoint.Transport != arden.TransportDirectTLS {
		return errors.New("arden/auth/gssapi: GSSAPI authentication-only mode requires direct TLS")
	}
	if endpoint.ServerName == "" {
		return errors.New("arden/auth/gssapi: endpoint TLS server name is empty")
	}
	return nil
}

// Begin creates a single per-connection GSS conversation. The GSS target is
// ldap@<Endpoint.ServerName>; Arden does not perform DNS canonicalization.
func (a *Authentication) Begin(ctx context.Context, endpoint arden.Endpoint) (arden.Authenticator, error) {
	if ctx == nil {
		return nil, errors.New("arden/auth/gssapi: nil authentication context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := a.ValidateEndpoint(endpoint); err != nil {
		return nil, err
	}
	provider, err := a.providerFactory()
	if err != nil {
		if !nilHandle(provider) {
			releaseErr := provider.Release()
			return nil, errors.Join(gssError(OperationNewProvider, err), gssError(OperationReleaseProvider, releaseErr))
		}
		return nil, gssError(OperationNewProvider, err)
	}
	if nilHandle(provider) {
		return nil, &NegotiationError{Step: StepContext, Failure: FailureNilHandle}
	}
	if err := ctx.Err(); err != nil {
		releaseErr := provider.Release()
		return nil, errors.Join(err, gssError(OperationReleaseProvider, releaseErr))
	}
	return &authenticator{
		identity:        a.identity,
		provider:        provider,
		target:          ldapServiceName + "@" + endpoint.ServerName,
		authorizationID: a.authorizationID,
		maxRounds:       a.maxRounds,
	}, nil
}

type authenticator struct {
	mu sync.Mutex

	identity        arden.Identity
	provider        gogssapi.Provider
	target          string
	authorizationID string
	maxRounds       int

	targetName gogssapi.GssName
	context    gogssapi.SecContext
	used       bool
	closed     bool
}

func (a *authenticator) Authenticate(ctx context.Context, session arden.InitializationSession) (arden.Identity, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if ctx == nil {
		return arden.Identity{}, errors.New("arden/auth/gssapi: nil authentication context")
	}
	if session == nil {
		return arden.Identity{}, errors.New("arden/auth/gssapi: nil initialization session")
	}
	if a.closed {
		return arden.Identity{}, errors.New("arden/auth/gssapi: authenticator is closed")
	}
	if a.used {
		return arden.Identity{}, errors.New("arden/auth/gssapi: authenticator was already used")
	}
	a.used = true

	if err := ctx.Err(); err != nil {
		return arden.Identity{}, err
	}
	name, err := a.provider.ImportName(a.target, gogssapi.GSS_NT_HOSTBASED_SERVICE)
	if err != nil {
		return arden.Identity{}, gssError(OperationImportName, err)
	}
	if nilHandle(name) {
		return arden.Identity{}, &NegotiationError{Step: StepContext, Failure: FailureNilHandle}
	}
	a.targetName = name
	if err := ctx.Err(); err != nil {
		return arden.Identity{}, err
	}

	securityContext, err := a.provider.InitSecContext(
		name,
		gogssapi.WithInitiatorMech(gogssapi.GSS_MECH_KRB5),
		gogssapi.WithInitiatorFlags(gogssapi.ContextFlagMutual|gogssapi.ContextFlagInteg),
	)
	if !nilHandle(securityContext) {
		a.context = securityContext
	}
	if err != nil {
		return arden.Identity{}, gssError(OperationInitContext, err)
	}
	if nilHandle(securityContext) {
		return arden.Identity{}, &NegotiationError{Step: StepContext, Failure: FailureNilHandle}
	}

	// go-gssapi providers retain or duplicate everything needed by the context.
	// Release the imported caller-owned name exactly once.
	a.targetName = nil
	if err := name.Release(); err != nil {
		return arden.Identity{}, gssError(OperationReleaseName, err)
	}
	if err := ctx.Err(); err != nil {
		return arden.Identity{}, err
	}

	serverToken, info, err := a.establishContext(ctx, session)
	if err != nil {
		return arden.Identity{}, err
	}
	defer clear(serverToken)
	if err := validateEstablishedContext(info); err != nil {
		return arden.Identity{}, err
	}
	if err := ctx.Err(); err != nil {
		return arden.Identity{}, err
	}

	offer, confidential, _, err := a.context.Unwrap(serverToken)
	if err != nil {
		return arden.Identity{}, gssError(OperationUnwrap, err)
	}
	defer clear(offer)
	if err := ctx.Err(); err != nil {
		return arden.Identity{}, err
	}
	if confidential {
		return arden.Identity{}, &NegotiationError{Step: StepSecurityLayer, Failure: FailureEncryptedSecurityOffer}
	}
	if len(offer) != 4 {
		return arden.Identity{}, &NegotiationError{Step: StepSecurityLayer, Failure: FailureInvalidSecurityOffer}
	}
	offeredLayers := offer[0]
	serverMaxBuffer := uint32(offer[1])<<16 | uint32(offer[2])<<8 | uint32(offer[3])
	if offeredLayers&layerNone == 0 {
		return arden.Identity{}, &NegotiationError{
			Step: StepSecurityLayer, Failure: FailureNoAuthenticationOnlyLayer, OfferedLayers: offeredLayers,
		}
	}
	if offeredLayers == layerNone && serverMaxBuffer != 0 {
		return arden.Identity{}, &NegotiationError{
			Step: StepSecurityLayer, Failure: FailureInvalidServerBuffer, OfferedLayers: offeredLayers,
		}
	}

	selection := make([]byte, 4+len(a.authorizationID))
	selection[0] = layerNone
	copy(selection[4:], a.authorizationID)
	wrappedSelection, confidential, err := a.context.Wrap(selection, false, 0)
	clear(selection)
	if err != nil {
		return arden.Identity{}, gssError(OperationWrap, err)
	}
	defer clear(wrappedSelection)
	if err := ctx.Err(); err != nil {
		return arden.Identity{}, err
	}
	if confidential {
		return arden.Identity{}, &NegotiationError{Step: StepSecurityLayer, Failure: FailureEncryptedLayerSelection}
	}

	result, err := exchangeBind(ctx, session, wrappedSelection)
	if err != nil {
		return arden.Identity{}, err
	}
	clear(wrappedSelection)
	if result.code != rfc4511.ResultSuccess {
		if result.code != rfc4511.ResultSASLBindInProgress {
			return arden.Identity{}, bindError(result.code)
		}
		return arden.Identity{}, &NegotiationError{
			Step: StepFinalBind, Failure: FailureUnexpectedLDAPResult, ResultCode: result.code,
		}
	}
	if result.hasCredentials && len(result.credentials) != 0 {
		clear(result.credentials)
		return arden.Identity{}, &NegotiationError{Step: StepFinalBind, Failure: FailureUnexpectedFinalCredentials}
	}
	clear(result.credentials)
	return a.identity, nil
}

func (a *authenticator) establishContext(ctx context.Context, session arden.InitializationSession) ([]byte, gogssapi.SecContextInfoPartial, error) {
	var inputToken []byte
	for range a.maxRounds {
		if err := ctx.Err(); err != nil {
			clear(inputToken)
			return nil, gogssapi.SecContextInfoPartial{}, err
		}
		outputToken, info, err := a.context.Continue(inputToken)
		clear(inputToken)
		if err != nil {
			clear(outputToken)
			return nil, gogssapi.SecContextInfoPartial{}, gssError(OperationContinue, err)
		}
		if err := ctx.Err(); err != nil {
			clear(outputToken)
			return nil, gogssapi.SecContextInfoPartial{}, err
		}

		continueNeeded := a.context.ContinueNeeded()
		if info.FullyEstablished == continueNeeded {
			clear(outputToken)
			return nil, gogssapi.SecContextInfoPartial{}, &NegotiationError{
				Step: StepContext, Failure: FailureInconsistentContextState,
			}
		}
		result, err := exchangeBind(ctx, session, outputToken)
		clear(outputToken)
		if err != nil {
			return nil, gogssapi.SecContextInfoPartial{}, err
		}
		if result.code != rfc4511.ResultSASLBindInProgress {
			clear(result.credentials)
			if result.code != rfc4511.ResultSuccess {
				return nil, gogssapi.SecContextInfoPartial{}, bindError(result.code)
			}
			return nil, gogssapi.SecContextInfoPartial{}, &NegotiationError{
				Step: StepContext, Failure: FailureUnexpectedLDAPResult, ResultCode: result.code,
			}
		}
		if !result.hasCredentials {
			return nil, gogssapi.SecContextInfoPartial{}, &NegotiationError{
				Step: StepContext, Failure: FailureMissingServerCredentials,
			}
		}
		if !continueNeeded {
			return result.credentials, info, nil
		}
		inputToken = result.credentials
	}
	clear(inputToken)
	return nil, gogssapi.SecContextInfoPartial{}, &NegotiationError{
		Step: StepContext, Failure: FailureTooManyRounds,
	}
}

func validateEstablishedContext(info gogssapi.SecContextInfoPartial) error {
	required := gogssapi.ContextFlagMutual | gogssapi.ContextFlagInteg
	if !info.FullyEstablished || info.Flags&required != required {
		return &NegotiationError{Step: StepContext, Failure: FailureMissingContextProtection}
	}
	if nilHandle(info.Mech) || !slices.Equal(info.Mech.Oid(), gogssapi.GSS_MECH_KRB5.Oid()) {
		return &NegotiationError{Step: StepContext, Failure: FailureWrongMechanism}
	}
	return nil
}

func nilHandle(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func (a *authenticator) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return nil
	}
	a.closed = true

	var errs []error
	if a.context != nil {
		securityContext := a.context
		a.context = nil
		token, err := securityContext.Delete()
		clear(token)
		if err != nil {
			errs = append(errs, gssError(OperationDeleteContext, err))
		}
	}
	if a.targetName != nil {
		name := a.targetName
		a.targetName = nil
		if err := name.Release(); err != nil {
			errs = append(errs, gssError(OperationReleaseName, err))
		}
	}
	if a.provider != nil {
		provider := a.provider
		a.provider = nil
		if err := provider.Release(); err != nil {
			errs = append(errs, gssError(OperationReleaseProvider, err))
		}
	}
	a.authorizationID = ""
	a.target = ""
	return errors.Join(errs...)
}

var (
	_ arden.Authentication                  = (*Authentication)(nil)
	_ arden.AuthenticationEndpointValidator = (*Authentication)(nil)
	_ arden.Authenticator                   = (*authenticator)(nil)
)
