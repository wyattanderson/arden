package rfc4511_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wyattanderson/arden"
	"github.com/wyattanderson/arden/ber"
	"github.com/wyattanderson/arden/rfc4511"
)

func TestOperationConstructors(t *testing.T) {
	type constructor func([]ber.Marshaler) (arden.Operation, error)
	tests := []struct {
		name         string
		construct    constructor
		requestID    ber.Identifier
		completeID   *ber.Identifier
		continueIDs  []ber.Identifier
		noResponse   bool
		cancellation arden.CancellationMode
		label        string
	}{
		{"bind", func(c []ber.Marshaler) (arden.Operation, error) {
			return rfc4511.NewBindOperation(&rfc4511.BindRequest{}, c)
		}, rfc4511.BindRequestIdentifier(), idPointer(rfc4511.BindResponseIdentifier()), nil, false, arden.CancelClose, "ldap.bind"},
		{"unbind", func(c []ber.Marshaler) (arden.Operation, error) {
			return rfc4511.NewUnbindOperation(&rfc4511.UnbindRequest{}, c)
		}, rfc4511.UnbindRequestIdentifier(), nil, nil, true, arden.CancelClose, "ldap.unbind"},
		{"search", func(c []ber.Marshaler) (arden.Operation, error) {
			return rfc4511.NewSearchOperation(&rfc4511.SearchRequest{}, c)
		}, rfc4511.SearchRequestIdentifier(), idPointer(rfc4511.SearchResultDoneIdentifier()), []ber.Identifier{rfc4511.SearchResultEntryIdentifier(), rfc4511.SearchResultReferenceIdentifier()}, false, arden.CancelAbandon, "ldap.search"},
		{"modify", func(c []ber.Marshaler) (arden.Operation, error) {
			return rfc4511.NewModifyOperation(&rfc4511.ModifyRequest{}, c)
		}, rfc4511.ModifyRequestIdentifier(), idPointer(rfc4511.ModifyResponseIdentifier()), nil, false, arden.CancelDrain, "ldap.modify"},
		{"add", func(c []ber.Marshaler) (arden.Operation, error) {
			return rfc4511.NewAddOperation(&rfc4511.AddRequest{}, c)
		}, rfc4511.AddRequestIdentifier(), idPointer(rfc4511.AddResponseIdentifier()), nil, false, arden.CancelDrain, "ldap.add"},
		{"delete", func(c []ber.Marshaler) (arden.Operation, error) {
			return rfc4511.NewDeleteOperation(&rfc4511.DeleteRequest{}, c)
		}, rfc4511.DeleteRequestIdentifier(), idPointer(rfc4511.DeleteResponseIdentifier()), nil, false, arden.CancelDrain, "ldap.delete"},
		{"modify DN", func(c []ber.Marshaler) (arden.Operation, error) {
			return rfc4511.NewModifyDNOperation(&rfc4511.ModifyDNRequest{}, c)
		}, rfc4511.ModifyDNRequestIdentifier(), idPointer(rfc4511.ModifyDNResponseIdentifier()), nil, false, arden.CancelDrain, "ldap.modify-dn"},
		{"compare", func(c []ber.Marshaler) (arden.Operation, error) {
			return rfc4511.NewCompareOperation(&rfc4511.CompareRequest{}, c)
		}, rfc4511.CompareRequestIdentifier(), idPointer(rfc4511.CompareResponseIdentifier()), nil, false, arden.CancelDrain, "ldap.compare"},
		{"abandon", func(c []ber.Marshaler) (arden.Operation, error) {
			return rfc4511.NewAbandonOperation(&rfc4511.AbandonRequest{}, c)
		}, rfc4511.AbandonRequestIdentifier(), nil, nil, true, arden.CancelNone, "ldap.abandon"},
		{"extended", func(c []ber.Marshaler) (arden.Operation, error) {
			return rfc4511.NewExtendedOperation(&rfc4511.ExtendedRequest{}, c)
		}, rfc4511.ExtendedRequestIdentifier(), idPointer(rfc4511.ExtendedResponseIdentifier()), []ber.Identifier{rfc4511.IntermediateResponseIdentifier()}, false, arden.CancelDrain, "ldap.extended"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			controls := []ber.Marshaler{rawControl{}}
			op, err := test.construct(controls)
			require.NoError(t, err)
			controls[0] = nil

			assert.Equal(t, test.requestID, op.Protocol.ProtocolIdentifier())
			assert.Equal(t, test.cancellation, op.Cancellation)
			assert.Equal(t, test.label, op.Metadata.Label)
			assert.Equal(t, test.noResponse, op.Responses.NoResponse())
			require.NoError(t, op.Validate(), "constructor must clone the controls slice")
			if test.completeID != nil {
				assert.Equal(t, arden.ClassificationComplete, op.Responses.Classify(*test.completeID))
			}
			for _, id := range test.continueIDs {
				assert.Equal(t, arden.ClassificationContinue, op.Responses.Classify(id))
			}
			if !test.noResponse {
				assert.Equal(t, arden.ClassificationInvalid, op.Responses.Classify(rfc4511.BindRequestIdentifier()))
			}
		})
	}
}

func TestOperationConstructorsRejectNilRequests(t *testing.T) {
	tests := []struct {
		name      string
		construct func() error
	}{
		{"bind", func() error { _, err := rfc4511.NewBindOperation(nil, nil); return err }},
		{"unbind", func() error { _, err := rfc4511.NewUnbindOperation(nil, nil); return err }},
		{"search", func() error { _, err := rfc4511.NewSearchOperation(nil, nil); return err }},
		{"modify", func() error { _, err := rfc4511.NewModifyOperation(nil, nil); return err }},
		{"add", func() error { _, err := rfc4511.NewAddOperation(nil, nil); return err }},
		{"delete", func() error { _, err := rfc4511.NewDeleteOperation(nil, nil); return err }},
		{"modify DN", func() error { _, err := rfc4511.NewModifyDNOperation(nil, nil); return err }},
		{"compare", func() error { _, err := rfc4511.NewCompareOperation(nil, nil); return err }},
		{"abandon", func() error { _, err := rfc4511.NewAbandonOperation(nil, nil); return err }},
		{"extended", func() error { _, err := rfc4511.NewExtendedOperation(nil, nil); return err }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.Error(t, test.construct())
		})
	}
}

func TestRequestMarshalersRejectNilReceiversAtomically(t *testing.T) {
	requests := []ber.Marshaler{
		(*rfc4511.BindRequest)(nil),
		(*rfc4511.SearchRequest)(nil),
		(*rfc4511.ModifyRequest)(nil),
		(*rfc4511.AddRequest)(nil),
		(*rfc4511.DeleteRequest)(nil),
		(*rfc4511.ModifyDNRequest)(nil),
		(*rfc4511.CompareRequest)(nil),
		(*rfc4511.AbandonRequest)(nil),
		(*rfc4511.ExtendedRequest)(nil),
	}
	for _, request := range requests {
		t.Run(requestTypeName(request), func(t *testing.T) {
			dst := []byte{0xde, 0xad}
			got, err := request.AppendBER(dst)
			require.Error(t, err)
			assert.Equal(t, dst, got)
		})
	}
}

func requestTypeName(request ber.Marshaler) string {
	return fmt.Sprintf("%T", request)
}

func idPointer(id ber.Identifier) *ber.Identifier { return &id }
