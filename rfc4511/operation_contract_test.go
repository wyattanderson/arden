package rfc4511

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wyattanderson/arden/ber"
	"github.com/wyattanderson/arden/protocol"
)

func TestOperationConstructors(t *testing.T) {
	type constructor func([]ber.Packeter) (protocol.AnyOperation, error)
	tests := []struct {
		name         string
		construct    constructor
		requestID    ber.Identifier
		completeID   *ber.Identifier
		continueIDs  []ber.Identifier
		noResponse   bool
		cancellation protocol.CancellationMode
		label        string
	}{
		{"bind", func(c []ber.Packeter) (protocol.AnyOperation, error) {
			return anyOperation(NewBindOperation(&BindRequest{}, c))
		}, BindRequestIdentifier(), new(BindResponseIdentifier()), nil, false, protocol.CancelClose, "ldap.bind"},
		{"unbind", func(c []ber.Packeter) (protocol.AnyOperation, error) {
			return anyOperation(NewUnbindOperation(&UnbindRequest{}, c))
		}, UnbindRequestIdentifier(), nil, nil, true, protocol.CancelClose, "ldap.unbind"},
		{"search", func(c []ber.Packeter) (protocol.AnyOperation, error) {
			return anyOperation(NewSearchOperation(&SearchRequest{}, c))
		}, SearchRequestIdentifier(), new(SearchResultDoneIdentifier()), []ber.Identifier{SearchResultEntryIdentifier(), SearchResultReferenceIdentifier()}, false, protocol.CancelAbandon, "ldap.search"},
		{"modify", func(c []ber.Packeter) (protocol.AnyOperation, error) {
			return anyOperation(NewModifyOperation(&ModifyRequest{}, c))
		}, ModifyRequestIdentifier(), new(ModifyResponseIdentifier()), nil, false, protocol.CancelDrain, "ldap.modify"},
		{"add", func(c []ber.Packeter) (protocol.AnyOperation, error) {
			return anyOperation(NewAddOperation(&AddRequest{}, c))
		}, AddRequestIdentifier(), new(AddResponseIdentifier()), nil, false, protocol.CancelDrain, "ldap.add"},
		{"delete", func(c []ber.Packeter) (protocol.AnyOperation, error) {
			return anyOperation(NewDeleteOperation(&DeleteRequest{}, c))
		}, DeleteRequestIdentifier(), new(DeleteResponseIdentifier()), nil, false, protocol.CancelDrain, "ldap.delete"},
		{"modify DN", func(c []ber.Packeter) (protocol.AnyOperation, error) {
			return anyOperation(NewModifyDNOperation(&ModifyDNRequest{}, c))
		}, ModifyDNRequestIdentifier(), new(ModifyDNResponseIdentifier()), nil, false, protocol.CancelDrain, "ldap.modify-dn"},
		{"compare", func(c []ber.Packeter) (protocol.AnyOperation, error) {
			return anyOperation(NewCompareOperation(&CompareRequest{}, c))
		}, CompareRequestIdentifier(), new(CompareResponseIdentifier()), nil, false, protocol.CancelDrain, "ldap.compare"},
		{"abandon", func(c []ber.Packeter) (protocol.AnyOperation, error) {
			return anyOperation(NewAbandonOperation(&AbandonRequest{}, c))
		}, AbandonRequestIdentifier(), nil, nil, true, protocol.CancelNone, "ldap.abandon"},
		{"extended", func(c []ber.Packeter) (protocol.AnyOperation, error) {
			return anyOperation(NewExtendedOperation(&ExtendedRequest{}, c))
		}, ExtendedRequestIdentifier(), new(ExtendedResponseIdentifier()), []ber.Identifier{IntermediateResponseIdentifier()}, false, protocol.CancelDrain, "ldap.extended"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			controls := []ber.Packeter{rawControl{}}
			typed, err := test.construct(controls)
			require.NoError(t, err)
			op := typed.Untyped()
			controls[0] = nil

			assert.Equal(t, test.requestID, op.Protocol.ProtocolIdentifier())
			assert.Equal(t, test.cancellation, op.Cancellation)
			assert.Equal(t, test.label, op.Metadata.Label)
			assert.Equal(t, test.noResponse, op.Responses.NoResponse())
			require.NoError(t, op.Validate(), "constructor must clone the controls slice")
			if test.completeID != nil {
				assert.Equal(t, protocol.ClassificationComplete, op.Responses.Classify(*test.completeID))
			}
			for _, id := range test.continueIDs {
				assert.Equal(t, protocol.ClassificationContinue, op.Responses.Classify(id))
			}
			if !test.noResponse {
				assert.Equal(t, protocol.ClassificationInvalid, op.Responses.Classify(BindRequestIdentifier()))
			}
		})
	}
}

func anyOperation[T any](operation protocol.Operation[T], err error) (protocol.AnyOperation, error) {
	return operation, err
}

func TestOperationConstructorsRejectNilRequests(t *testing.T) {
	tests := []struct {
		name      string
		construct func() error
	}{
		{"bind", func() error { _, err := NewBindOperation(nil, nil); return err }},
		{"unbind", func() error { _, err := NewUnbindOperation(nil, nil); return err }},
		{"search", func() error { _, err := NewSearchOperation(nil, nil); return err }},
		{"modify", func() error { _, err := NewModifyOperation(nil, nil); return err }},
		{"add", func() error { _, err := NewAddOperation(nil, nil); return err }},
		{"delete", func() error { _, err := NewDeleteOperation(nil, nil); return err }},
		{"modify DN", func() error { _, err := NewModifyDNOperation(nil, nil); return err }},
		{"compare", func() error { _, err := NewCompareOperation(nil, nil); return err }},
		{"abandon", func() error { _, err := NewAbandonOperation(nil, nil); return err }},
		{"extended", func() error { _, err := NewExtendedOperation(nil, nil); return err }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.Error(t, test.construct())
		})
	}
}

func TestRequestPacketersPanicOnNilReceivers(t *testing.T) {
	requests := []ber.Packeter{
		(*BindRequest)(nil),
		(*SearchRequest)(nil),
		(*ModifyRequest)(nil),
		(*AddRequest)(nil),
		(*DeleteRequest)(nil),
		(*ModifyDNRequest)(nil),
		(*CompareRequest)(nil),
		(*AbandonRequest)(nil),
		(*ExtendedRequest)(nil),
	}
	for _, request := range requests {
		t.Run(requestTypeName(request), func(t *testing.T) {
			assert.Panics(t, func() { request.BERPacket() })
		})
	}
}

func requestTypeName(request ber.Packeter) string {
	return fmt.Sprintf("%T", request)
}
