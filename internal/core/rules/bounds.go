package rules

import (
	"unicode/utf8"

	"github.com/ericfitz/agentmesh/internal/bus"
)

// The bounds of api/openapi.yaml that no older rule owns (issue #34). Each is
// a named constant so the spec test can read it. Who chose each value is in
// the ADR 0001 addendum: MaxLabelRunes, MaxTokenBytes, the metadata constants
// and MaxArrayItems are Eric's rule (b) values of 2026-11-06; MaxQueryRunes is
// a plan ruling (Eric may overrule); MaxSearchCursorLen follows from the
// cursor's format.
const (
	// MaxLabelRunes bounds a short free-form string (a message type, a status
	// tag), in characters.
	MaxLabelRunes = 256
	// MaxTokenBytes bounds an opaque token (a session id, an ack, an
	// idempotency key, an enrollment token), in bytes.
	MaxTokenBytes = 1024
	// MaxMetadataKeys, MaxMetadataKeyRunes and MaxMetadataValueRunes bound a
	// metadata map: its entries, and a key and a value in characters.
	MaxMetadataKeys       = 32
	MaxMetadataKeyRunes   = 64
	MaxMetadataValueRunes = 1024
	// MaxArrayItems bounds a request array.
	MaxArrayItems = 256
	// MaxQueryRunes bounds a search query, in characters.
	MaxQueryRunes = 1024
	// MaxSearchCursorLen is the digits of math.MaxInt64: a search cursor is a
	// decimal offset.
	MaxSearchCursorLen = 19
	// SearchCursorPattern is the shape of a search cursor for api/openapi.yaml.
	SearchCursorPattern = "^[0-9]+$"
)

func tooLong(field string, limit int, unit string) error {
	return bus.Errorf(bus.CodeValidation, false, "%s must be at most %d %s", field, limit, unit)
}

// CheckLabel refuses s when it is longer than MaxLabelRunes characters.
func CheckLabel(field, s string) error {
	if utf8.RuneCountInString(s) > MaxLabelRunes {
		return tooLong(field, MaxLabelRunes, "characters")
	}
	return nil
}

// CheckToken refuses s when it is longer than MaxTokenBytes bytes.
func CheckToken(field, s string) error {
	if len(s) > MaxTokenBytes {
		return tooLong(field, MaxTokenBytes, "bytes")
	}
	return nil
}

// CheckMetadata refuses a map of more than MaxMetadataKeys entries, a key
// longer than MaxMetadataKeyRunes characters or a value longer than
// MaxMetadataValueRunes characters. nil passes.
func CheckMetadata(m map[string]string) error {
	if len(m) > MaxMetadataKeys {
		return bus.Errorf(bus.CodeValidation, false, "metadata has %d keys, at most %d", len(m), MaxMetadataKeys)
	}
	for k, v := range m {
		if utf8.RuneCountInString(k) > MaxMetadataKeyRunes {
			return bus.Errorf(bus.CodeValidation, false, "metadata key %q must be at most %d characters", k, MaxMetadataKeyRunes)
		}
		if utf8.RuneCountInString(v) > MaxMetadataValueRunes {
			return bus.Errorf(bus.CodeValidation, false, "metadata value for key %q must be at most %d characters", k, MaxMetadataValueRunes)
		}
	}
	return nil
}

// CheckItems refuses an array of more than MaxArrayItems entries.
func CheckItems(field string, n int) error {
	if n > MaxArrayItems {
		return bus.Errorf(bus.CodeValidation, false, "%s has %d entries, at most %d", field, n, MaxArrayItems)
	}
	return nil
}

// NonNegative refuses a negative v.
func NonNegative(field string, v int64) error {
	if v < 0 {
		return bus.Errorf(bus.CodeValidation, false, "%s must not be negative", field)
	}
	return nil
}

// AtLeastOne refuses a v below 1.
func AtLeastOne(field string, v int64) error {
	if v < 1 {
		return bus.Errorf(bus.CodeValidation, false, "%s must be at least 1", field)
	}
	return nil
}
