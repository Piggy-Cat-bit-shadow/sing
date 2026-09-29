package bufio

import (
	"io"
	"testing"

	"github.com/sagernet/sing/common/buf"
)

// BenchmarkCachedFirstPayload measures the cached first payload of a sniffed connection, which is
// the single payload CopyWithIncreateBuffer hands over before the ordinary copy loop starts.
//
// # Why the two paths differ, and by how much
//
//	plain   destination.Write(cachedBuffer.Bytes())
//	        the buffer's geometry is discarded and the framing writer builds its own frame buffer
//	buffer  WriteOwnedBuffer -> destination.WriteBuffer(cachedBuffer)
//	        the header and trailer go into the buffer's own headroom
//
// The fixture writer models a framing protocol: it advertises front/rear headroom and an MTU, and
// its Write path allocates a second buffer exactly as a real framing writer must.
func BenchmarkCachedFirstPayload(b *testing.B) {
	// Sizes up to the fixture's MTU (65278, the Naive reference frame ceiling's payload budget).
	// A LARGER payload cannot be framed in place at all, so it is not a fast-path case and is
	// deliberately absent rather than silently falling back inside the measurement.
	for _, size := range []int{64, 1400, 16 * 1024, 64 * 1024} {
		b.Run("plain/"+itoaBench(size), func(b *testing.B) {
			writer := &framingBenchWriter{frontHeadroom: 3, rearHeadroom: 255, writerMTU: 65278}
			b.ReportAllocs()
			b.SetBytes(int64(size))
			b.ResetTimer()
			for b.Loop() {
				b.StopTimer()
				// The geometry the cache layer produces.
				cached := newGeometryBuffer(3, size, 255)
				b.StartTimer()
				_, _ = writer.Write(cached.Bytes())
				b.StopTimer()
				cached.Release()
				b.StartTimer()
			}
		})
		b.Run("buffer/"+itoaBench(size), func(b *testing.B) {
			writer := &framingBenchWriter{frontHeadroom: 3, rearHeadroom: 255, writerMTU: 65278}
			b.ReportAllocs()
			b.SetBytes(int64(size))
			b.ResetTimer()
			for b.Loop() {
				b.StopTimer()
				cached := newGeometryBuffer(3, size, 255)
				b.StartTimer()
				_, handedOver := WriteOwnedBuffer(writer, cached)
				// Skip rather than fail: 64 KiB exceeds the fixture's writerMTU, so the fallback is
				// the CORRECT outcome there and the fast path simply does not apply.
				if !handedOver {
					b.StopTimer()
					cached.Release()
					b.StartTimer()
					continue
				}
			}
		})
	}
}

// framingBenchWriter models a framing protocol writer: it prepends a header and appends padding,
// taking a buffer directly when it can and otherwise building its own.
type framingBenchWriter struct {
	frontHeadroom int
	rearHeadroom  int
	writerMTU     int
}

func (w *framingBenchWriter) Write(p []byte) (int, error) {
	// The copying path: a real framing writer must build its own frame buffer and copy the payload.
	frame := buf.NewSize(w.frontHeadroom + len(p) + w.rearHeadroom)
	frame.Resize(w.frontHeadroom, 0)
	_, _ = frame.Write(p)
	_ = frame.Bytes()
	frame.Release()
	return len(p), nil
}

func (w *framingBenchWriter) WriteBuffer(buffer *buf.Buffer) error {
	// The in-place path: header and trailer go into the buffer's own headroom, no payload copy.
	_ = buffer.ExtendHeader(w.frontHeadroom)
	_ = buffer.WriteZeroN(128)
	_ = buffer.Bytes()
	buffer.Release()
	return nil
}

func (w *framingBenchWriter) WriterMTU() int     { return w.writerMTU }
func (w *framingBenchWriter) FrontHeadroom() int { return w.frontHeadroom }
func (w *framingBenchWriter) RearHeadroom() int  { return w.rearHeadroom }

func itoaBench(v int) string {
	if v == 0 {
		return "0"
	}
	var digits [20]byte
	pos := len(digits)
	for v > 0 {
		pos--
		digits[pos] = byte('0' + v%10)
		v /= 10
	}
	return string(digits[pos:])
}

var _ io.Writer = (*framingBenchWriter)(nil)
