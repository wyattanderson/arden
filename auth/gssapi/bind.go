package gssapi

import (
	"context"
	"errors"
	"io"

	"github.com/wyattanderson/arden"
	"github.com/wyattanderson/arden/auth"
	"github.com/wyattanderson/arden/ber"
	"github.com/wyattanderson/arden/rfc4511"
)

const (
	layerNone            byte = 1
	layerIntegrity       byte = 2
	layerConfidentiality byte = 4
)

type bindResult struct {
	code           rfc4511.ResultCode
	credentials    []byte
	hasCredentials bool
}

func exchangeBind(ctx context.Context, session arden.InitializationSession, token []byte) (bindResult, error) {
	// The caller keeps token alive for this exchange and clears it afterward.
	request := &rfc4511.BindRequest{
		Version: 3,
		Authentication: rfc4511.SASLAuthentication{
			Mechanism:      rfc4511.LDAPString("GSSAPI"),
			Credentials:    token,
			HasCredentials: true,
		},
	}
	operation, err := rfc4511.NewBindOperation(request, nil)
	if err != nil {
		return bindResult{}, err
	}
	stream, err := session.Do(ctx, operation)
	if err != nil {
		return bindResult{}, err
	}
	response, err := stream.Next(ctx)
	if err != nil {
		return bindResult{}, err
	}
	defer clear(response.Bytes)

	decoded, err := operation.Responses.Decode(response, ber.DefaultLimits())
	if err != nil {
		return bindResult{}, err
	}
	if _, err := stream.Next(ctx); !errors.Is(err, io.EOF) {
		if err == nil {
			return bindResult{}, errors.New("arden/auth/gssapi: Bind returned more than one response")
		}
		return bindResult{}, err
	}
	return bindResult{
		code:           decoded.Result.ResultCode,
		credentials:    decoded.ServerSASLCredentials,
		hasCredentials: decoded.HasServerSASLCredentials,
	}, nil
}

func bindError(code rfc4511.ResultCode) error {
	return &auth.BindError{ResultCode: code}
}
