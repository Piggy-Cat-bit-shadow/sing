package byteformats

import (
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

// Tests that a byte-limit literal cannot silently wrap.
//
// # The bug
//
// parseUnit computed `b.value = value * unitValue` with no overflow check, so a
// literal whose product exceeds MaxUint64 wrapped silently and returned no error.
// Measured before the fix:
//
//	"16e"     -> 0                     (2^64 wrapped to zero)
//	"16384p"  -> 0
//	"17e"     -> 1152921504606846976   (wrapped, not zero, and equally wrong)
//
// # Why silently matters
//
// These types carry resource limits - Naive's stream_receive_window,
// quic_session_receive_window, cache sizes. Consumers treat 0 as "not set" and fall
// back to a default, so `"stream_receive_window": "16e"` was accepted without
// complaint and then ignored. That is a configuration option accepted and silently
// discarded: the operator believes a 16 EiB window is configured while the default
// is in force. A wrapped non-zero value is worse still, because it looks deliberate.
//
// The bare-integer branch had the same class of defect: it unmarshals into an int64
// and casts to uint64, so a negative literal became a huge positive limit.

// TestMemoryBytesOverflowIsRejected covers the binary units.
func TestMemoryBytesOverflowIsRejected(t *testing.T) {
	overflowing := []string{
		`"16e"`,                   // 16 * 2^60 = 2^64
		`"17e"`,                   // wraps to a non-zero value
		`"16384p"`,                // 2^14 * 2^50 = 2^64
		`"18446744073709551615e"`, // maximal wrap
		`"18014398509481984t"`,    // 2^54 * 2^40 = 2^94
		`"18446744073709551615"`,  // quoted digits with no unit are not a valid literal
		`18446744073709551616`,    // one past MaxUint64 as a JSON number
		`"-1"`,
		`"-9223372036854775808"`,
	}
	for _, literal := range overflowing {
		var value MemoryBytes
		err := value.UnmarshalJSON([]byte(literal))
		require.Error(t, err,
			"%s must be rejected rather than wrapping silently; parsing produced %d",
			literal, value.Value())
	}
}

// TestMemoryBytesAcceptsValuesUpToTheBoundary is the control. A check that rejected
// everything legitimate would pass the test above while breaking real configuration.
func TestMemoryBytesAcceptsValuesUpToTheBoundary(t *testing.T) {
	valid := []struct {
		literal string
		value   uint64
	}{
		{`8388608`, 8388608}, // the production stream_receive_window, as a JSON number
		{`"8m"`, 8 << 20},
		{`"1g"`, 1 << 30},
		{`33554432`, 33554432}, // the production connection window, as a JSON number
		{`"32m"`, 32 << 20},
		{`"0"`, 0},
		{`"15e"`, 15 << 60},                         // the largest whole EiB value that fits
		{`"18446744073709551615b"`, math.MaxUint64}, // MaxUint64 in bytes
		{`"1023p"`, 1023 << 50},                     // just under the 2^64 boundary for PiB
		{`"18014398509481983b"`, 18014398509481983}, // 2^54 - 1 bytes, exact
	}
	for _, testCase := range valid {
		var value MemoryBytes
		err := value.UnmarshalJSON([]byte(testCase.literal))
		require.NoError(t, err, "%s is a legitimate value and must be accepted",
			testCase.literal)
		require.Equal(t, testCase.value, value.Value(),
			"%s must parse to its exact value, not a wrapped or clamped one",
			testCase.literal)
	}
}

// TestBytesAndNetworkBytesAlsoRejectOverflow proves the check is in the shared
// parser rather than patched into MemoryBytes only.
func TestBytesAndNetworkBytesAlsoRejectOverflow(t *testing.T) {
	// Bytes uses DECIMAL units, where e = 10^18, so 16e (1.6e19) still fits under
	// MaxUint64 (1.8e19). 19e does not.
	var plain Bytes
	require.Error(t, plain.UnmarshalJSON([]byte(`"19e"`)),
		"Bytes shares parseUnit, so it must reject the overflow too")
	require.NoError(t, plain.UnmarshalJSON([]byte(`"16e"`)),
		"and it must still accept 16e, which fits")

	var network NetworkBytes
	require.Error(t, network.UnmarshalJSON([]byte(`"18446744073709551615Gbps"`)),
		"NetworkBytes shares parseUnit, so it must reject the overflow too")
}

// TestExactBoundaryIsNotRejected pins the boundary itself, so the guard cannot be
// tightened into false rejections.
func TestExactBoundaryIsNotRejected(t *testing.T) {
	// The largest value that fits exactly: MaxUint64 / 1EiB, times 1EiB.
	const eiByte = uint64(1) << 60
	largest := math.MaxUint64 / eiByte
	var value MemoryBytes
	require.NoError(t, value.UnmarshalJSON([]byte(`"`+itoa(largest)+`e"`)),
		"the largest value that fits exactly must be accepted")
	require.Equal(t, largest*eiByte, value.Value())

	// One more must be refused, and the refusal must not be off by one.
	var overflow MemoryBytes
	require.Error(t, overflow.UnmarshalJSON([]byte(`"`+itoa(largest+1)+`e"`)),
		"one unit more than fits must be refused")
}

// TestNegativeValuesAreRejected covers the int64-to-uint64 cast.
func TestNegativeValuesAreRejected(t *testing.T) {
	for _, literal := range []string{`"-1"`, `"-100"`, `"-9223372036854775808"`} {
		var value MemoryBytes
		err := value.UnmarshalJSON([]byte(literal))
		require.Error(t, err,
			"%s must be rejected: casting a negative int64 to uint64 would make it "+
				"an enormous positive limit", literal)
	}
	// A negative value with a unit is not parseable as int64 and fails earlier.
	var withUnit MemoryBytes
	require.Error(t, withUnit.UnmarshalJSON([]byte(`"-1m"`)))
}

// TestMalformedInputsStillRejected guards the pre-existing behaviour.
func TestMalformedInputsStillRejected(t *testing.T) {
	for _, literal := range []string{`"abc"`, `"m"`, `""`, `"1x"`, `"1 m m"`, `"-1m"`} {
		var value MemoryBytes
		require.Error(t, value.UnmarshalJSON([]byte(literal)),
			"%s is malformed and must be rejected", literal)
	}
}

// TestRoundTripOfAcceptedValues proves the marshaller still agrees with the parser.
func TestRoundTripOfAcceptedValues(t *testing.T) {
	for _, literal := range []string{`"8m"`, `"1g"`, `"0"`, `"0m"`, `8388608`, `33554432`} {
		var original MemoryBytes
		require.NoError(t, original.UnmarshalJSON([]byte(literal)))

		encoded, err := original.MarshalJSON()
		require.NoError(t, err)

		var decoded MemoryBytes
		require.NoError(t, decoded.UnmarshalJSON(encoded),
			"re-parsing %s (encoded as %s) must succeed", literal, encoded)
		require.Equal(t, original.Value(), decoded.Value(),
			"round-tripping %s must preserve the value", literal)
	}
}

func itoa(n uint64) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}
