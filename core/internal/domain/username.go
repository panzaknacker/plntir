package domain

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

const MaxUsernameRunes = 32

var ErrReservedUsername = errors.New("username is reserved")

var reservedUsernames = map[string]struct{}{
	"admin":         {},
	"administrator": {},
	"api":           {},
	"contact":       {},
	"files":         {},
	"masteradmin":   {},
	"mdm":           {},
	"plntir":        {},
	"root":          {},
	"share":         {},
	"support":       {},
	"system":        {},
	"wazuh":         {},
}

type Username struct {
	Display   string
	Canonical string
}

// ParseUsername applies the public identity rules in one place. Display names
// are NFC-normalized, while uniqueness uses unicode default case folding.
func ParseUsername(raw string) (Username, error) {
	if !utf8.ValidString(raw) {
		return Username{}, errors.New("username is not valid UTF-8")
	}
	display := norm.NFC.String(raw)
	if display == "" {
		return Username{}, errors.New("username is empty")
	}
	if strings.TrimSpace(display) != display {
		return Username{}, errors.New("username cannot start or end with whitespace")
	}
	count := 0
	visible := 0
	previousSpace := false
	for _, r := range display {
		count++
		switch {
		case r == ' ':
			if previousSpace {
				return Username{}, errors.New("username cannot contain repeated spaces")
			}
			previousSpace = true
			visible++
		case unicode.IsControl(r), unicode.In(r, unicode.Cf, unicode.Cs, unicode.Co, unicode.Zl, unicode.Zp):
			return Username{}, fmt.Errorf("username contains prohibited U+%04X", r)
		case unicode.IsSpace(r):
			return Username{}, fmt.Errorf("username contains unsupported whitespace U+%04X", r)
		default:
			previousSpace = false
			if !unicode.Is(unicode.Mn, r) && !unicode.Is(unicode.Me, r) {
				visible++
			}
		}
	}
	if count > MaxUsernameRunes {
		return Username{}, fmt.Errorf("username exceeds %d Unicode characters", MaxUsernameRunes)
	}
	if visible == 0 {
		return Username{}, errors.New("username has no visible characters")
	}
	canonical := norm.NFC.String(cases.Fold().String(display))
	if _, reserved := reservedUsernames[canonical]; reserved {
		return Username{}, ErrReservedUsername
	}
	return Username{Display: display, Canonical: canonical}, nil
}
