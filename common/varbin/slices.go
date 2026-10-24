package varbin

import (
	"slices"

	"github.com/sagernet/sing/common/binary"
)

type BaseData interface {
	~bool | ~int8 | ~uint8 | ~int16 | ~uint16 | ~int32 | ~uint32 | ~int64 | ~uint64 | ~float32 | ~float64
}

func ReadSlice[T BaseData](reader Reader, order binary.ByteOrder) ([]T, error) {
	count, err := binary.ReadUvarint(reader)
	if err != nil {
		return nil, err
	}
	return ReadSliceCount[T](reader, order, count)
}

// maxInitialChunk bounds the first allocation of a counted slice. It is deliberately small: the
// count is attacker-controlled, and a forged uvarint must never be able to turn into a large
// up-front allocation before the input has proved it actually contains that many bytes.
const maxInitialChunk = 1024

func ReadSliceCount[T BaseData](reader Reader, order binary.ByteOrder, count uint64) ([]T, error) {
	var result []T
	for uint64(len(result)) < count {
		if len(result) == cap(result) {
			// Grow geometrically. The previous form asked slices.Grow for ONE element on every
			// iteration, so a large decoded array was copied on every step: measured at 5-6x the
			// final slice in total allocation for rule-set matchers, which is exactly the transient
			// that dominates a large rule-set load. A doubling step costs about 2x while keeping
			// the first allocation bounded.
			growth := uint64(cap(result))
			if growth < maxInitialChunk {
				growth = maxInitialChunk
			}
			growth = min(growth, count-uint64(len(result)))
			result = slices.Grow(result, int(growth))
		}
		chunkCount := min(count-uint64(len(result)), uint64(cap(result)-len(result)))
		start := len(result)
		result = result[:uint64(start)+chunkCount]
		err := binary.Read(reader, order, result[start:])
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}
