package rfc4511_test

import (
	"testing"

	"github.com/wyattanderson/arden"
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
			if got := test.identifier; got.Class != ber.ClassApplication || got.Number != test.number || got.Constructed != test.constructed {
				t.Fatalf("identifier = %s, want application/%v/%d", got, test.constructed, test.number)
			}
		})
	}
}

func TestResultCodeAndPatternInventory(t *testing.T) {
	for _, test := range []struct {
		code rfc4511.ResultCode
		want int64
	}{
		{rfc4511.ResultSuccess, 0},
		{rfc4511.ResultReferral, 10},
		{rfc4511.ResultSASLBindInProgress, 14},
		{rfc4511.ResultEntryAlreadyExists, 68},
		{rfc4511.ResultOther, 80},
	} {
		if int64(test.code) != test.want {
			t.Fatalf("result code %d, want %d", test.code, test.want)
		}
	}

	tests := []struct {
		name    string
		pattern arden.ResponsePattern
		id      ber.Identifier
		want    arden.Classification
	}{
		{"bind", rfc4511.BindResponsePattern(), rfc4511.BindResponseIdentifier(), arden.ClassificationComplete},
		{"add", rfc4511.AddResponsePattern(), rfc4511.AddResponseIdentifier(), arden.ClassificationComplete},
		{"modify", rfc4511.ModifyResponsePattern(), rfc4511.ModifyResponseIdentifier(), arden.ClassificationComplete},
		{"delete", rfc4511.DeleteResponsePattern(), rfc4511.DeleteResponseIdentifier(), arden.ClassificationComplete},
		{"modify DN", rfc4511.ModifyDNResponsePattern(), rfc4511.ModifyDNResponseIdentifier(), arden.ClassificationComplete},
		{"compare", rfc4511.CompareResponsePattern(), rfc4511.CompareResponseIdentifier(), arden.ClassificationComplete},
		{"extended terminal", rfc4511.ExtendedResponsePattern(), rfc4511.ExtendedResponseIdentifier(), arden.ClassificationComplete},
		{"extended intermediate", rfc4511.ExtendedResponsePattern(), rfc4511.IntermediateResponseIdentifier(), arden.ClassificationContinue},
	}
	for _, test := range tests {
		if got := test.pattern.Classify(test.id); got != test.want {
			t.Fatalf("%s pattern = %v, want %v", test.name, got, test.want)
		}
	}
	if !rfc4511.UnbindResponsePattern().NoResponse() || !rfc4511.AbandonResponsePattern().NoResponse() {
		t.Fatal("no-response patterns are not declared")
	}
}
