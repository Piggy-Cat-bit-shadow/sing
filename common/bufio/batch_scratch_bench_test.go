package bufio

import (
	"fmt"
	"testing"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// Benchmarks for the per-batch scratch arrays used by the packet batch copy loops.
//
// # What is being measured
//
// Every batch copy iteration used to allocate its own bookkeeping slices:
//
//	dataLens := make([]int, len(buffers))          // and int64 in the counter writers
//	destinations := make([]M.Socksaddr, len(buffers))
//
// That is one or two allocations per batch on the hottest UDP path in the process -
// the one carrying game, VoIP, QUIC and video-call traffic. The scratch arrays remove
// them, so these benchmarks exist to show the difference rather than assert it.
//
// # Why allocs/op is the number that matters
//
// The per-iteration work is dominated by the payload itself, so ns/op moves little. The
// cost being removed is allocator traffic and the GC pressure that follows it on a
// phone, and allocs/op and B/op measure exactly that.
//
// Run with -benchmem; allocs/op is the headline.

// benchBatchSizes covers the range the batch path actually sees. 1 is the degenerate
// case (no batching), and DefaultPacketReadBatchSize is the largest the read waiter is
// configured for by default.
var benchBatchSizes = []int{1, 8, 32, DefaultPacketReadBatchSize}

// benchmarkBatchReader produces batches of the requested size from a fixed payload,
// using fresh buffers each round so the measurement includes real buffer handling.
type benchmarkBatchReader struct {
	destination M.Socksaddr
	batchSize   int
	rounds      int
}

func (r *benchmarkBatchReader) InitializeReadWaiter(options N.ReadWaitOptions) bool {
	if options.BatchSize > 0 {
		r.batchSize = options.BatchSize
	}
	return true
}

func (r *benchmarkBatchReader) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	return M.Socksaddr{}, errBenchmarkReaderExhausted
}

func (r *benchmarkBatchReader) WaitReadConnectedPackets() ([]*buf.Buffer, M.Socksaddr, error) {
	buffers, destinations, err := r.WaitReadPackets()
	if err != nil {
		return nil, M.Socksaddr{}, err
	}
	return buffers, destinations[0], nil
}

func (r *benchmarkBatchReader) WaitReadPackets() ([]*buf.Buffer, []M.Socksaddr, error) {
	if r.rounds <= 0 {
		return nil, nil, errBenchmarkReaderExhausted
	}
	r.rounds--
	buffers := make([]*buf.Buffer, r.batchSize)
	destinations := make([]M.Socksaddr, r.batchSize)
	for i := range buffers {
		buffer := buf.NewSize(1400)
		buffer.Extend(256)
		buffers[i] = buffer
		destinations[i] = r.destination
	}
	return buffers, destinations, nil
}

// BenchmarkPacketBatchCopyAllocations measures the copy loop into a batch writer.
//
// It uses the same connected-batch fixtures as the correctness tests so the path under
// measurement is the production one, not a stand-in.
func BenchmarkPacketBatchCopyAllocations(b *testing.B) {
	destination := M.ParseSocksaddr("192.0.2.1:443")

	for _, batchSize := range benchBatchSizes {
		b.Run(fmt.Sprintf("batch-%d", batchSize), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				writer := &countingBatchWriter{}
				session := &packetCopySession{}
				source := &benchmarkBatchReader{
					destination: destination,
					batchSize:   batchSize,
					rounds:      1,
				}
				b.StartTimer()

				_, _, err := copyConnectedPacketBatchWaitWithPool(session, writer, source, false)
				if err != nil && err != errBenchmarkReaderExhausted {
					b.Fatal(err)
				}
			}
		})
	}
}

// countingBatchWriter consumes batches and discards them, so the measurement covers the
// bookkeeping rather than any assertion work.
type countingBatchWriter struct {
	batches int
	packets int
}

func (w *countingBatchWriter) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	buffer.Release()
	return nil
}

func (w *countingBatchWriter) WritePacketBatch(buffers []*buf.Buffer, destinations []M.Socksaddr) error {
	w.batches++
	w.packets += len(buffers)
	buf.ReleaseMulti(buffers)
	return nil
}

func (w *countingBatchWriter) WriteConnectedPacketBatch(buffers []*buf.Buffer) error {
	w.batches++
	w.packets += len(buffers)
	buf.ReleaseMulti(buffers)
	return nil
}

// BenchmarkCounterBatchWriterAllocations isolates the counter writer's own scratch use.
//
// The counter wrapper also built an int64 dataLens per batch, on the same path, so it is
// measured separately from the copy loop it sits inside.
func BenchmarkCounterBatchWriterAllocations(b *testing.B) {
	destination := M.ParseSocksaddr("192.0.2.1:443")

	for _, batchSize := range benchBatchSizes {
		b.Run(fmt.Sprintf("batch-%d", batchSize), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				inner := &countingBatchWriter{}
				writer := &counterPacketBatchWriter{
					writer:      inner,
					writeCounts: []N.CountFunc{func(int64) {}},
				}
				buffers := make([]*buf.Buffer, batchSize)
				destinations := make([]M.Socksaddr, batchSize)
				for j := range buffers {
					buffer := buf.NewSize(1400)
					buffer.Extend(256)
					buffers[j] = buffer
					destinations[j] = destination
				}
				b.StartTimer()

				if err := writer.WritePacketBatch(buffers, destinations); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

var errBenchmarkReaderExhausted = fmt.Errorf("benchmark reader exhausted")

// BenchmarkBatchScratchAllocation isolates the scratch arrays themselves.
//
// The full copy-loop benchmark cannot show this cleanly: the loop must allocate its
// payload buffers, and those allocations dominate the count. This measures the exact
// decision the change makes - "does building the per-batch bookkeeping allocate?" -
// against the same code written the old way, so the comparison is of one thing only.
//
// The old form is reproduced here rather than checked out, because both must be in the
// same binary for a fair comparison.
func BenchmarkBatchScratchAllocation(b *testing.B) {
	for _, batchSize := range benchBatchSizes {
		b.Run(fmt.Sprintf("scratch-%d", batchSize), func(b *testing.B) {
			// Declared once, as the copy loops now declare it.
			var scratch batchScratch
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				sink = scratch.ints(batchSize)
				sink64 = scratch.int64s(batchSize)
				sinkDest = scratch.destinations(batchSize)
			}
		})
	}
}

func BenchmarkBatchScratchAllocationOldForm(b *testing.B) {
	for _, batchSize := range benchBatchSizes {
		b.Run(fmt.Sprintf("make-%d", batchSize), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				sink = make([]int, batchSize)
				sink64 = make([]int64, batchSize)
				sinkDest = make([]M.Socksaddr, batchSize)
			}
		})
	}
}

// Package-level sinks keep the compiler from eliminating the allocations.
var (
	sink     []int
	sink64   []int64
	sinkDest []M.Socksaddr
)
