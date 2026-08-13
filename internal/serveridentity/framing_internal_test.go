package serveridentity

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// These tests exercise the unexported framing helpers directly and therefore
// only compile against the round-7 framed implementation. They pin the
// injectivity property at the serialization level.

// Identical data under different component tags must produce different hash
// inputs: the component domain is part of the serialized input, so the same
// bytes can never be re-interpreted between executable content and argument
// content.
func TestFramingTagSeparatesDomains(t *testing.T) {
	data := []byte("shared-bytes")
	hExec, hArg := sha256.New(), sha256.New()
	writeField(hExec, tagExecutable, 0, data)
	writeField(hArg, tagArgument, 0, data)
	if hex.EncodeToString(hExec.Sum(nil)) == hex.EncodeToString(hArg.Sum(nil)) {
		t.Fatal("P1: tag must separate component domains in the serialized input")
	}
}

// Identical data at different ordinal indexes must produce different hash
// inputs: position is part of the serialized input.
func TestFramingIndexSeparatesPositions(t *testing.T) {
	data := []byte("arg")
	h0, h1 := sha256.New(), sha256.New()
	writeField(h0, tagArgument, 0, data)
	writeField(h1, tagArgument, 1, data)
	if hex.EncodeToString(h0.Sum(nil)) == hex.EncodeToString(h1.Sum(nil)) {
		t.Fatal("P1: index must separate ordinal positions in the serialized input")
	}
}

// The serialized input must be self-delimiting: a field's data bytes must
// never be confused with the following field's header, even when the data
// itself contains bytes that look like a tag, index, or length. This is the
// injectivity property at the framing level: parse(tag|index|length|data)
// is unambiguous because length is fixed-width and precedes the data.
func TestFramingFieldSelfDelimiting(t *testing.T) {
	// Data that embeds a plausible tag/length prefix must not merge with a
	// following field.
	evilData := append([]byte{tagArgument}, make([]byte, 8)...) // tag + zero index bytes
	evilData = append(evilData, 0x08, 0x00)                     // plausible length + junk

	withField, concatenated := sha256.New(), sha256.New()
	// (1) one field with data evilData
	writeField(withField, tagExecutable, 0, evilData)
	// (2) two fields: one with the prefix, one with the rest
	writeField(concatenated, tagExecutable, 0, evilData[:9])
	writeField(concatenated, tagArgument, 0, evilData[9:])

	if hex.EncodeToString(withField.Sum(nil)) == hex.EncodeToString(concatenated.Sum(nil)) {
		t.Fatal("P1: framed fields must be self-delimiting; embedded header-like bytes must not merge fields")
	}
}
