package varbin

import (
	"bytes"
	stdBinary "encoding/binary"
	"runtime"
	"testing"
)

func encodeUint64Slice(count uint64) []byte {
	payload := stdBinary.AppendUvarint(nil, count)
	for i := uint64(0); i < count; i++ {
		payload = stdBinary.BigEndian.AppendUint64(payload, i)
	}
	return payload
}

// A large counted slice must not copy itself on every element.
//
// The old growth step asked for one element at a time, so the cumulative allocation was several
// times the final slice. This pins the geometric behaviour with a bound that the old code cannot
// meet while leaving room for the allocator's size classes.
func TestReadSliceCountAllocatesGeometrically(t *testing.T) {
	const count = 1 << 20
	payload := encodeUint64Slice(count)

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	values, err := ReadSlice[uint64](bytes.NewReader(payload), stdBinary.BigEndian)
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatal(err)
	}
	runtime.KeepAlive(values)
	if len(values) != count {
		t.Fatalf("decoded %d values, want %d", len(values), count)
	}
	if values[0] != 0 || values[count-1] != count-1 {
		t.Fatalf("decoded values are not the encoded ones")
	}
	finalBytes := uint64(count) * 8
	allocated := after.TotalAlloc - before.TotalAlloc
	// One-element growth measures 5-6x. Doubling plus the final slice must stay well below 3x.
	if allocated > 3*finalBytes {
		t.Fatalf("decoding %d elements allocated %d bytes (%.1fx the final %d), want under 3x",
			count, allocated, float64(allocated)/float64(finalBytes), finalBytes)
	}
}

// A forged count must fail cheaply. The budget here is the first chunk, not the claimed count.
func TestReadSliceCountDoesNotPreallocateAForgedCount(t *testing.T) {
	payload := stdBinary.AppendUvarint(nil, 1<<40)
	payload = append(payload, 1, 2, 3, 4)

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	_, err := ReadSlice[uint64](bytes.NewReader(payload), stdBinary.BigEndian)
	runtime.ReadMemStats(&after)
	if err == nil {
		t.Fatal("a count the input cannot satisfy must fail")
	}
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 64<<10 {
		t.Fatalf("a forged count allocated %d bytes before the input proved its length", allocated)
	}
}

// initialChunkForTest mirrors varbin.maxInitialChunk so the table stays compilable against the
// pre-change implementation when the red proof is re-run.
const initialChunkForTest = 1024

func TestReadSliceCountSmallCounts(t *testing.T) {
	for _, count := range []uint64{0, 1, 2, 3, 17, initialChunkForTest - 1, initialChunkForTest, initialChunkForTest + 1} {
		payload := encodeUint64Slice(count)
		values, err := ReadSlice[uint64](bytes.NewReader(payload), stdBinary.BigEndian)
		if err != nil {
			t.Fatalf("count %d: %v", count, err)
		}
		if uint64(len(values)) != count {
			t.Fatalf("count %d: decoded %d values", count, len(values))
		}
		for i := range values {
			if values[i] != uint64(i) {
				t.Fatalf("count %d: value %d = %d", count, i, values[i])
			}
		}
	}
}
