package domain

import (
	"errors"
	"strings"
	"testing"
)

func TestParseUsernameNormalizesAndCaseFolds(t *testing.T) {
	composed, err := ParseUsername("Caf\u00e9 User")
	if err != nil {
		t.Fatal(err)
	}
	decomposed, err := ParseUsername("Cafe\u0301 user")
	if err != nil {
		t.Fatal(err)
	}
	if composed.Display != "Caf\u00e9 User" {
		t.Fatalf("display is not NFC: %q", composed.Display)
	}
	if composed.Canonical != decomposed.Canonical {
		t.Fatalf("canonicals differ: %q != %q", composed.Canonical, decomposed.Canonical)
	}

	street, err := ParseUsername("Stra\u00dfe")
	if err != nil {
		t.Fatal(err)
	}
	upper, err := ParseUsername("STRASSE")
	if err != nil {
		t.Fatal(err)
	}
	if street.Canonical != upper.Canonical {
		t.Fatalf("full case fold did not match: %q != %q", street.Canonical, upper.Canonical)
	}
}

func TestParseUsernameAllowsVisibleUnicodeAndEmoji(t *testing.T) {
	got, err := ParseUsername("Mira \U0001F680")
	if err != nil {
		t.Fatal(err)
	}
	if got.Display != "Mira \U0001F680" {
		t.Fatalf("unexpected display %q", got.Display)
	}
}

func TestParseUsernameRejectsInvisibleBidiAndSystemNames(t *testing.T) {
	for _, value := range []string{
		" leading",
		"trailing ",
		"two  spaces",
		"zero\u200bwidth",
		"right\u202eto-left",
		"line\nbreak",
		strings.Repeat("a", MaxUsernameRunes+1),
	} {
		if _, err := ParseUsername(value); err == nil {
			t.Errorf("username %q unexpectedly validated", value)
		}
	}
	if _, err := ParseUsername("AdMiN"); !errors.Is(err, ErrReservedUsername) {
		t.Fatalf("expected reserved-name error, got %v", err)
	}
}
