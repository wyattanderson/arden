package rfc4511_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/wyattanderson/arden/ber"
	"github.com/wyattanderson/arden/rfc4511"
)

func TestRFC4511ApplicationIdentifierInventory(t *testing.T) {
	tests := []struct {
		name        string
		identifier  ber.Identifier
		number      uint32
		constructed bool
	}{
		{"bind request", rfc4511.BindRequestIdentifier(), 0, true},
		{"bind response", rfc4511.BindResponseIdentifier(), 1, true},
		{"unbind request", rfc4511.UnbindRequestIdentifier(), 2, false},
		{"search request", rfc4511.SearchRequestIdentifier(), 3, true},
		{"search entry", rfc4511.SearchResultEntryIdentifier(), 4, true},
		{"search done", rfc4511.SearchResultDoneIdentifier(), 5, true},
		{"modify request", rfc4511.ModifyRequestIdentifier(), 6, true},
		{"modify response", rfc4511.ModifyResponseIdentifier(), 7, true},
		{"add request", rfc4511.AddRequestIdentifier(), 8, true},
		{"add response", rfc4511.AddResponseIdentifier(), 9, true},
		{"delete request", rfc4511.DeleteRequestIdentifier(), 10, false},
		{"delete response", rfc4511.DeleteResponseIdentifier(), 11, true},
		{"modify DN request", rfc4511.ModifyDNRequestIdentifier(), 12, true},
		{"modify DN response", rfc4511.ModifyDNResponseIdentifier(), 13, true},
		{"compare request", rfc4511.CompareRequestIdentifier(), 14, true},
		{"compare response", rfc4511.CompareResponseIdentifier(), 15, true},
		{"abandon request", rfc4511.AbandonRequestIdentifier(), 16, false},
		{"search reference", rfc4511.SearchResultReferenceIdentifier(), 19, true},
		{"extended request", rfc4511.ExtendedRequestIdentifier(), 23, true},
		{"extended response", rfc4511.ExtendedResponseIdentifier(), 24, true},
		{"intermediate response", rfc4511.IntermediateResponseIdentifier(), 25, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, ber.ClassApplication, test.identifier.Class)
			assert.Equal(t, test.number, test.identifier.Number)
			assert.Equal(t, test.constructed, test.identifier.Constructed)
		})
	}
}
