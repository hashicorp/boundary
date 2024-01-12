package fuzz

import (
	"regexp"
	"strings"
	"testing"
)

var (
	ourDNSRegex       = regexp.MustCompile(`^[a-z0-9-]{0,62}[a-z0-9](\.([a-z0-9-]{0,62}[a-z0-9]))*$`)
	ourSubstringCheck = regexp.MustCompile(`^[0-9]+$`)
)

// From https://github.com/golang/go/blob/2540b1436ff452529b1668a8310411ddea826c52/src/net/dnsclient.go#L72-L132
func netdnsIsDomainName(s string) bool {
	// The root domain name is valid. See golang.org/issue/45715.
	if s == "." {
		return true
	}

	// See RFC 1035, RFC 3696.
	// Presentation format has dots before every label except the first, and the
	// terminal empty label is optional here because we assume fully-qualified
	// (absolute) input. We must therefore reserve space for the first and last
	// labels' length octets in wire format, where they are necessary and the
	// maximum total length is 255.
	// So our _effective_ maximum is 253, but 254 is not rejected if the last
	// character is a dot.
	l := len(s)
	if l == 0 || l > 254 || l == 254 && s[l-1] != '.' {
		return false
	}

	last := byte('.')
	nonNumeric := false // true once we've seen a letter or hyphen
	partlen := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		default:
			return false
		case 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || c == '_':
			nonNumeric = true
			partlen++
		case '0' <= c && c <= '9':
			// fine
			partlen++
		case c == '-':
			// Byte before dash cannot be dot.
			if last == '.' {
				return false
			}
			partlen++
			nonNumeric = true
		case c == '.':
			// Byte before dot cannot be dot, dash.
			if last == '.' || last == '-' {
				return false
			}
			if partlen > 63 || partlen == 0 {
				return false
			}
			partlen = 0
		}
		last = c
	}
	if last == '-' || partlen > 63 {
		return false
	}

	return nonNumeric
}

func isValidDNSHostname(s string) bool {
	if len(s) == 0 {
		return false
	}
	if len(s) > 253 {
		return false
	}
	if strings.TrimSpace(s) != s {
		return false
	}
	if s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	if !ourDNSRegex.MatchString(strings.ToLower(s)) {
		return false
	}
	for _, split := range strings.Split(s, ".") {
		if split[0] == '-' || split[len(split)-1] == '-' {
			return false
		}
	}
	if dotIndex := strings.LastIndex(s, "."); ourSubstringCheck.MatchString(s[dotIndex+1:]) {
		return false
	}
	return true
}

func FuzzDNSValidator(f *testing.F) {
	f.Add([]byte("google.com"))
	f.Add([]byte("boundary.hashicorp.com"))

	f.Fuzz(func(t *testing.T, input []byte) {
		acceptedByUs := isValidDNSHostname(string(input))
		acceptedByNetDNS := netdnsIsDomainName(string(input))
		//acceptedByValidator := govalidator.IsDNSName(string(input))

		switch {
		case !acceptedByUs && acceptedByNetDNS:
			t.Errorf("%q was rejected by us but not by net package", string(input))
		//case !acceptedByUs && acceptedByValidator:
		//	t.Errorf("%q was rejected by us but not by govalidator", string(input))
		case acceptedByUs && !acceptedByNetDNS:
			t.Errorf("%q was accepted by us but not by net package", string(input))
			//case acceptedByUs && !acceptedByValidator:
			//	t.Errorf("%q was accepted by us but not by govalidator", string(input))
		}
	})
}
