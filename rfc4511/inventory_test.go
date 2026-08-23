package rfc4511

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/wyattanderson/arden/ber"
)

func TestRFC4511ApplicationIdentifierInventory(t *testing.T) {
	tests := []struct {
		name        string
		identifier  ber.Identifier
		number      uint32
		constructed bool
	}{
		{"bind request", BindRequestIdentifier(), 0, true},
		{"bind response", BindResponseIdentifier(), 1, true},
		{"unbind request", UnbindRequestIdentifier(), 2, false},
		{"search request", SearchRequestIdentifier(), 3, true},
		{"search entry", SearchResultEntryIdentifier(), 4, true},
		{"search done", SearchResultDoneIdentifier(), 5, true},
		{"modify request", ModifyRequestIdentifier(), 6, true},
		{"modify response", ModifyResponseIdentifier(), 7, true},
		{"add request", AddRequestIdentifier(), 8, true},
		{"add response", AddResponseIdentifier(), 9, true},
		{"delete request", DeleteRequestIdentifier(), 10, false},
		{"delete response", DeleteResponseIdentifier(), 11, true},
		{"modify DN request", ModifyDNRequestIdentifier(), 12, true},
		{"modify DN response", ModifyDNResponseIdentifier(), 13, true},
		{"compare request", CompareRequestIdentifier(), 14, true},
		{"compare response", CompareResponseIdentifier(), 15, true},
		{"abandon request", AbandonRequestIdentifier(), 16, false},
		{"search reference", SearchResultReferenceIdentifier(), 19, true},
		{"extended request", ExtendedRequestIdentifier(), 23, true},
		{"extended response", ExtendedResponseIdentifier(), 24, true},
		{"intermediate response", IntermediateResponseIdentifier(), 25, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, ber.ClassApplication, test.identifier.Class)
			assert.Equal(t, test.number, test.identifier.Number)
			assert.Equal(t, test.constructed, test.identifier.Constructed)
		})
	}
}
