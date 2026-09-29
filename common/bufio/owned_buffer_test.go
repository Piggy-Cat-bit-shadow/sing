package bufio

import (
	"errors"
	"sync"
	"testing"

	"github.com/sagernet/sing/common/buf"

	"github.com/stretchr/testify/require"
)

// Tests for WriteOwnedBuffer, the geometry-based ownership hand-off used for a cached first payload.
//
// # The property
//
// The decision must follow the destination writer's OWN advertised geometry and nothing else. When
// the buffer fits, the writer takes ownership and the caller must not release; when it does not,
// the original path runs and the caller releases. Getting the second half wrong leaks a pooled
// buffer, and getting the first half wrong double-releases one.

// geometryDestination records how it was written to, and advertises configurable geometry.
type geometryDestination struct {
	access sync.Mutex

	frontHeadroom int
	rearHeadroom  int
	writerMTU     int

	bufferWrites    int
	plainWrites     int
	lastPlainData   []byte
	lastBufferLen   int
	failWriteBuffer bool
	// releases counts handovers the fixture released, which is the ownership record.
	releases int
}

func (d *geometryDestination) Write(p []byte) (int, error) {
	d.access.Lock()
	defer d.access.Unlock()
	d.plainWrites++
	d.lastPlainData = append([]byte(nil), p...)
	return len(p), nil
}

func (d *geometryDestination) writeBuffer(buffer *buf.Buffer) error {
	// The release is a DEFER, before the error is known, because that is what every real
	// N.ExtendedWriter does:
	//
	//	ExtendedWriterWrapper.WriteBuffer: defer buffer.Release(); return common.Error(w.Write(...))
	//	ChunkWriter.WriteBuffer:           defer buffer.Release() on the oversized branch
	//
	// An earlier version of this fixture released only on the SUCCESS path. That modelled a
	// contract no writer has, and it is why WriteOwnedBuffer's double release went unnoticed: the
	// test asserted the wrong behaviour and the fixture quietly agreed.
	defer func() {
		d.access.Lock()
		d.releases++
		d.access.Unlock()
		buffer.Release()
	}()

	d.access.Lock()
	defer d.access.Unlock()
	if d.failWriteBuffer {
		d.bufferWrites++
		return errors.New("test: WriteBuffer failed")
	}
	d.bufferWrites++
	d.lastBufferLen = buffer.Len()
	return nil
}

// releaseCount reports how many times the fixture released a handover. It is the ownership RECORD:
// buf.Buffer.Release() is idempotent from the outside, so "did the caller also release" is not
// observable on the buffer itself.
func (d *geometryDestination) releaseCount() int {
	d.access.Lock()
	defer d.access.Unlock()
	return d.releases
}

// fullGeometry has both capability sets plus the extended writer.
type fullGeometry struct{ *geometryDestination }

func (d fullGeometry) WriteBuffer(buffer *buf.Buffer) error { return d.writeBuffer(buffer) }
func (d fullGeometry) WriterMTU() int                       { return d.geometryDestination.writerMTU }
func (d fullGeometry) FrontHeadroom() int {
	return d.geometryDestination.frontHeadroom
}
func (d fullGeometry) RearHeadroom() int { return d.geometryDestination.rearHeadroom }

// bufferOnly accepts buffers but advertises no geometry.
type bufferOnly struct{ *geometryDestination }

func (d bufferOnly) WriteBuffer(buffer *buf.Buffer) error { return d.writeBuffer(buffer) }

// plainOnly has no buffer capability at all.
type plainOnly struct{ *geometryDestination }

// mtuOnly advertises an MTU but no headroom.
type mtuOnly struct{ *geometryDestination }

func (d mtuOnly) WriteBuffer(buffer *buf.Buffer) error { return d.writeBuffer(buffer) }
func (d mtuOnly) WriterMTU() int                       { return d.geometryDestination.writerMTU }

// newGeometryBuffer builds a pooled buffer with the given headroom, payload and spare capacity.
//
// spare is a parameter because rear headroom is one of the checks; a fixture that always left
// plenty would make that check untestable.
func newGeometryBuffer(headroom, payloadLen, spare int) *buf.Buffer {
	buffer := buf.NewSize(headroom + payloadLen + spare)
	buffer.Resize(headroom, 0)
	for index := 0; index < payloadLen; index++ {
		_ = buffer.WriteByte(byte(index))
	}
	return buffer
}

// TestWriteOwnedBufferHandsOverWhenGeometryFits is the fast path.
func TestWriteOwnedBufferHandsOverWhenGeometryFits(t *testing.T) {
	t.Parallel()

	destination := &geometryDestination{frontHeadroom: 3, rearHeadroom: 255, writerMTU: 65278}
	cached := newGeometryBuffer(64, 1000, 512)
	payloadLen := cached.Len()

	err, handedOver := WriteOwnedBuffer(fullGeometry{destination}, cached)
	require.NoError(t, err)
	require.True(t, handedOver, "a buffer with the writer's geometry must be handed over")

	destination.access.Lock()
	defer destination.access.Unlock()
	require.Equal(t, 1, destination.bufferWrites, "WriteBuffer must have been used")
	require.Zero(t, destination.plainWrites, "the copying path must not have been used")
	require.Equal(t, payloadLen, destination.lastBufferLen)
}

// TestWriteOwnedBufferFallsBackPerRequirement checks each geometry requirement independently, so a
// single accidentally-passing case cannot hide a missing check.
func TestWriteOwnedBufferFallsBackPerRequirement(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		name       string
		front      int
		rear       int
		mtu        int
		headroom   int
		payloadLen int
		spare      int
		reason     string
	}{
		{
			name: "payload exceeds WriterMTU", front: 3, rear: 255, mtu: 512,
			headroom: 64, payloadLen: 1000, spare: 512,
			reason: "a payload larger than the writer's MTU must not be handed over",
		},
		{
			name: "insufficient front headroom", front: 3, rear: 255, mtu: 65278,
			headroom: 1, payloadLen: 100, spare: 512,
			reason: "the writer cannot prepend its header, so the buffer must be copied",
		},
		{
			name: "insufficient rear headroom", front: 3, rear: 255, mtu: 65278,
			headroom: 64, payloadLen: 100, spare: 10,
			reason: "the writer cannot append its trailer, so the buffer must be copied",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			destination := &geometryDestination{
				frontHeadroom: testCase.front,
				rearHeadroom:  testCase.rear,
				writerMTU:     testCase.mtu,
			}
			cached := newGeometryBuffer(testCase.headroom, testCase.payloadLen, testCase.spare)
			expected := append([]byte(nil), cached.Bytes()...)

			err, handedOver := WriteOwnedBuffer(fullGeometry{destination}, cached)
			require.NoError(t, err)
			require.False(t, handedOver, testCase.reason)

			destination.access.Lock()
			defer destination.access.Unlock()
			require.Equal(t, 1, destination.plainWrites, "the fallback must go through Write")
			require.Zero(t, destination.bufferWrites, "the buffer must NOT be handed over")
			require.Equal(t, expected, destination.lastPlainData, "the fallback must carry the same bytes")
			cached.Release()
		})
	}
}

// TestWriteOwnedBufferWithoutExtendedWriter covers a destination with no buffer capability.
func TestWriteOwnedBufferWithoutExtendedWriter(t *testing.T) {
	t.Parallel()

	destination := &geometryDestination{}
	cached := newGeometryBuffer(64, 256, 512)
	expected := append([]byte(nil), cached.Bytes()...)

	err, handedOver := WriteOwnedBuffer(plainOnly{destination}, cached)
	require.NoError(t, err)
	require.False(t, handedOver)

	destination.access.Lock()
	defer destination.access.Unlock()
	require.Equal(t, 1, destination.plainWrites)
	require.Equal(t, expected, destination.lastPlainData)
	cached.Release()
}

// TestWriteOwnedBufferOwnershipOnError is the ownership case that matters most.
//
// # The contract this asserts, and the one it used to assert
//
// Ownership transfers the moment WriteBuffer is ENTERED, and the error result does not change that:
// every N.ExtendedWriter releases the buffer with a `defer`, which runs on the error path too. So a
// failed WriteBuffer must still report handedOver=true and the caller must NOT release.
//
// The previous version asserted the opposite -- that a failed WriteBuffer leaves the buffer with the
// caller -- and the fixture cooperated by releasing only on success. Both were wrong, and together
// they hid a real double release.
//
// # Why the assertion is on the release COUNT
//
// buf.Buffer.Release() is idempotent from the outside: it zeroes the struct and clears its managed
// flag, so a second call is a silent no-op and `cached.Len() == 0` holds either way. Asserting on
// Len would therefore pass with the bug present. The count is the ownership record.
func TestWriteOwnedBufferOwnershipOnError(t *testing.T) {
	t.Parallel()

	destination := &geometryDestination{
		frontHeadroom: 3, rearHeadroom: 255, writerMTU: 65278,
		failWriteBuffer: true,
	}
	cached := newGeometryBuffer(64, 100, 512)

	err, handedOver := WriteOwnedBuffer(fullGeometry{destination}, cached)
	require.Error(t, err, "the writer's error must be reported")
	require.True(t, handedOver,
		"a FAILED WriteBuffer still transfers ownership: the writer releases with a defer, so the "+
			"caller must not release or the pool array is handed out twice")
	require.Equal(t, 1, destination.releaseCount(),
		"the writer must have released exactly once")
	require.Zero(t, cached.Len(), "the writer's deferred release cleared the buffer")
}

// TestWriteOwnedBufferWithNoAdvertisedGeometry proves a buffer-taking writer that advertises nothing
// still gets the buffer: there is no requirement to violate.
func TestWriteOwnedBufferWithNoAdvertisedGeometry(t *testing.T) {
	t.Parallel()

	destination := &geometryDestination{}
	cached := newGeometryBuffer(8, 4096, 512)

	err, handedOver := WriteOwnedBuffer(bufferOnly{destination}, cached)
	require.NoError(t, err)
	require.True(t, handedOver, "a writer that advertises no geometry has none to satisfy")

	destination.access.Lock()
	defer destination.access.Unlock()
	require.Equal(t, 1, destination.bufferWrites)
}

// TestWriteOwnedBufferChecksOnlyAdvertisedGeometry proves an MTU-only writer is checked on its MTU
// and not on headroom it never asked for.
func TestWriteOwnedBufferChecksOnlyAdvertisedGeometry(t *testing.T) {
	t.Parallel()

	destination := &geometryDestination{writerMTU: 512}

	// Within the MTU, and with no headroom at all: must be handed over, because this writer never
	// advertised a headroom requirement.
	fitting := newGeometryBuffer(0, 256, 64)
	err, handedOver := WriteOwnedBuffer(mtuOnly{destination}, fitting)
	require.NoError(t, err)
	require.True(t, handedOver, "a writer with no headroom requirement must not be failed for headroom")

	// Over the MTU: must fall back.
	oversized := newGeometryBuffer(0, 1000, 64)
	expected := append([]byte(nil), oversized.Bytes()...)
	err, handedOver = WriteOwnedBuffer(mtuOnly{destination}, oversized)
	require.NoError(t, err)
	require.False(t, handedOver, "an oversized payload must still fall back")
	destination.access.Lock()
	require.Equal(t, expected, destination.lastPlainData)
	destination.access.Unlock()
	oversized.Release()
}

// TestWriteOwnedBufferBothPathsCarryTheSameBytes is the correctness guard across the two paths.
func TestWriteOwnedBufferBothPathsCarryTheSameBytes(t *testing.T) {
	t.Parallel()

	fastDestination := &geometryDestination{frontHeadroom: 3, rearHeadroom: 255, writerMTU: 65278}
	fastBuffer := newGeometryBuffer(64, 8192, 512)
	viaFast := append([]byte(nil), fastBuffer.Bytes()...)
	err, handedOver := WriteOwnedBuffer(fullGeometry{fastDestination}, fastBuffer)
	require.NoError(t, err)
	require.True(t, handedOver)

	strictDestination := &geometryDestination{writerMTU: 1}
	slowBuffer := newGeometryBuffer(64, 8192, 512)
	viaSlow := append([]byte(nil), slowBuffer.Bytes()...)
	err, handedOver = WriteOwnedBuffer(mtuOnly{strictDestination}, slowBuffer)
	require.NoError(t, err)
	require.False(t, handedOver)
	slowBuffer.Release()

	require.Equal(t, viaFast, viaSlow, "both paths must carry identical bytes")
}
