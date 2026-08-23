// Package rfc4532 implements the LDAP Who Am I? extended operation.
package rfc4532

import (
	"context"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"

	"github.com/wyattanderson/arden/ber"
	"github.com/wyattanderson/arden/protocol"
	"github.com/wyattanderson/arden/rfc4511"
)

// OID is the Who Am I? request object identifier.
const OID rfc4511.LDAPOID = "1.3.6.1.4.1.4203.1.11.3"

// ResultError reports a non-success LDAP result returned by Who Am I?.
type ResultError struct {
	Result rfc4511.LDAPResult
}

func (e *ResultError) Error() string {
	return fmt.Sprintf("rfc4532: Who Am I? failed with LDAP result code %d", e.Result.ResultCode)
}

// ResultCode returns the server's LDAP result code.
func (e *ResultError) ResultCode() rfc4511.ResultCode { return e.Result.ResultCode }

// WhoAmI returns the authorization identity currently associated with executor.
// An empty identity represents an anonymous authorization state.
func WhoAmI(ctx context.Context, executor protocol.Executor) (string, error) {
	if executor == nil {
		return "", errors.New("rfc4532: nil executor")
	}
	operation, err := rfc4511.NewExtendedOperation(&rfc4511.ExtendedRequest{Name: OID}, nil)
	if err != nil {
		return "", err
	}
	stream, err := executor.Do(ctx, operation)
	if err != nil {
		return "", err
	}
	//nolint:errcheck // The terminal response determines the operation result.
	defer stream.Close()

	message, err := stream.Next(ctx)
	if err != nil {
		return "", err
	}
	if message.ProtocolID != rfc4511.ExtendedResponseIdentifier() {
		return "", fmt.Errorf("rfc4532: unexpected response identifier %s", message.ProtocolID)
	}
	var response rfc4511.ExtendedResponse
	if err := message.UnmarshalProtocol(&response, ber.DefaultLimits()); err != nil {
		return "", err
	}
	if _, err := stream.Next(ctx); !errors.Is(err, io.EOF) {
		if err == nil {
			err = errors.New("rfc4532: Who Am I? returned more than one response")
		}
		return "", err
	}
	if response.Result.ResultCode != rfc4511.ResultSuccess {
		return "", &ResultError{Result: response.Result}
	}
	if response.HasResponseName {
		return "", errors.New("rfc4532: Who Am I? returned an unexpected response name")
	}
	if !response.HasResponseValue {
		return "", errors.New("rfc4532: Who Am I? omitted the authorization identity")
	}
	if !utf8.Valid(response.ResponseValue) {
		return "", errors.New("rfc4532: Who Am I? returned a non-UTF-8 authorization identity")
	}
	return string(response.ResponseValue), nil
}
