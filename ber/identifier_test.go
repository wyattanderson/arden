package ber_test

import (
	"testing"

	"github.com/wyattanderson/arden/ber"
)

func TestIdentifierValidityAndString(t *testing.T) {
	id := ber.Identifier{Class: ber.ClassApplication, Constructed: true, Number: 25}
	if !id.Valid() {
		t.Fatal("valid application identifier rejected")
	}
	if got, want := id.String(), "application/constructed/25"; got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
	if (ber.Identifier{Class: 4}).Valid() {
		t.Fatal("out-of-range class accepted")
	}
}
