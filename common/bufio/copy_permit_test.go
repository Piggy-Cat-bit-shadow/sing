package bufio

// The growth-boundary permit seam added for JiejieBox's relay GrowthBudget.
//
// The contract these tests pin:
//
//   - the seam is not asked before the configured IncreaseBufferAfter threshold, so a
//     direction that never grows never charges the caller;
//   - a grant switches the read buffer at the threshold and its release runs exactly
//     once, when the copy returns;
//   - a refusal keeps the small buffer and is re-asked only at a bounded milestone, so
//     a direction refused under pressure can still grow later without a per-read
//     callback;
//   - every exit path (EOF, read error, write error) releases exactly once;
//   - a nil seam behaves exactly like the old code.

import (
	"errors"
	"io"
	"sync"
	"testing"

	"github.com/sagernet/sing/common/buf"
	N "github.com/sagernet/sing/common/network"
)

// permitRecorder is a seam that answers from a script and records its calls and release.
type permitRecorder struct {
	access   sync.Mutex
	grants   []bool
	asked    int
	released int
}

func (r *permitRecorder) seam() (func(), bool) {
	r.access.Lock()
	defer r.access.Unlock()
	r.asked++
	granted := true
	if r.asked <= len(r.grants) {
		granted = r.grants[r.asked-1]
	}
	if !granted {
		return nil, false
	}
	return func() {
		r.access.Lock()
		r.released++
		r.access.Unlock()
	}, true
}

func (r *permitRecorder) counts() (asked int, released int) {
	r.access.Lock()
	defer r.access.Unlock()
	return r.asked, r.released
}

// permitReader produces a fixed payload and records every requested read size.
type permitReader struct {
	remaining int
	sizes     []int
	readErr   error
}

func (r *permitReader) Read(p []byte) (int, error) {
	r.sizes = append(r.sizes, len(p))
	if r.remaining <= 0 {
		if r.readErr != nil {
			return 0, r.readErr
		}
		return 0, io.EOF
	}
	n := min(len(p), r.remaining)
	for index := 0; index < n; index++ {
		p[index] = 'p'
	}
	r.remaining -= n
	return n, nil
}

func grownPermitReads(sizes []int) int {
	grown := 0
	for _, size := range sizes {
		if size > buf.BufferSize {
			grown++
		}
	}
	return grown
}

// permitWriter accepts writes until its limit, then fails (or succeeds forever when
// limit is negative). It records the sizes it was handed.
type permitWriter struct {
	written int
	limit   int
	onLimit error
}

func (w *permitWriter) Write(p []byte) (int, error) {
	if w.limit >= 0 && w.written+len(p) > w.limit {
		return 0, w.onLimit
	}
	w.written += len(p)
	return len(p), nil
}

func TestIncreaseBufferPermitNotAskedBeforeTheThreshold(t *testing.T) {
	permit := &permitRecorder{}
	reader := &permitReader{remaining: 100 * 1000}
	writer := &permitWriter{limit: -1}
	copied, err := CopyWithIncreateBufferPermit(writer, reader, DefaultIncreaseBufferAfter, DefaultBatchSize, permit.seam)
	if err != nil {
		t.Fatal(err)
	}
	if copied != 100*1000 {
		t.Fatalf("copied %d bytes, expected %d", copied, 100*1000)
	}
	if asked, released := permit.counts(); asked != 0 || released != 0 {
		t.Fatalf("a direction that copied less than the threshold must not ask the seam: asked=%d released=%d", asked, released)
	}
	if grown := grownPermitReads(reader.sizes); grown != 0 {
		t.Fatalf("a direction below the threshold must keep the small buffer, got %d grown reads", grown)
	}
}

func TestIncreaseBufferPermitGrantedAtThresholdAndReleasedOnce(t *testing.T) {
	permit := &permitRecorder{}
	reader := &permitReader{remaining: 2 << 20}
	writer := &permitWriter{limit: -1}
	_, err := CopyWithIncreateBufferPermit(writer, reader, DefaultIncreaseBufferAfter, DefaultBatchSize, permit.seam)
	if err != nil {
		t.Fatal(err)
	}
	asked, released := permit.counts()
	if asked != 1 {
		t.Fatalf("the seam must be asked exactly once on the way to a grant, got %d", asked)
	}
	if released != 1 {
		t.Fatalf("the release must run exactly once when the copy returns, got %d", released)
	}
	if grown := grownPermitReads(reader.sizes); grown == 0 {
		t.Fatal("a granted direction must switch to the enlarged buffer")
	}
	if reader.sizes[0] != buf.BufferSize {
		t.Fatalf("the first read must use the small buffer, got %d", reader.sizes[0])
	}
}

func TestIncreaseBufferPermitRefusalKeepsTheSmallBufferAndRetriesAtMilestones(t *testing.T) {
	permit := &permitRecorder{grants: []bool{false, false, false, false, false}}
	reader := &permitReader{remaining: 3 << 20}
	writer := &permitWriter{limit: -1}
	_, err := CopyWithIncreateBufferPermit(writer, reader, DefaultIncreaseBufferAfter, DefaultBatchSize, permit.seam)
	if err != nil {
		t.Fatal(err)
	}
	asked, released := permit.counts()
	// The threshold crossing asks; each refusal schedules another attempt only after at
	// least increaseBufferRetryStep further bytes. 3 MiB comfortably covers the
	// threshold plus one retry milestone, and must not be a per-read callback.
	if asked < 2 || asked > 3 {
		t.Fatalf("a refused direction must be re-asked at bounded milestones, got %d asks for 3 MiB", asked)
	}
	if released != 0 {
		t.Fatalf("a refusal must not produce a release, got %d", released)
	}
	if grown := grownPermitReads(reader.sizes); grown != 0 {
		t.Fatalf("a refused direction must keep the small buffer, got %d grown reads", grown)
	}
}

func TestIncreaseBufferPermitCanGrowAfterAnEarlierRefusal(t *testing.T) {
	permit := &permitRecorder{grants: []bool{false, true}}
	reader := &permitReader{remaining: 2 << 20}
	writer := &permitWriter{limit: -1}
	_, err := CopyWithIncreateBufferPermit(writer, reader, DefaultIncreaseBufferAfter, DefaultBatchSize, permit.seam)
	if err != nil {
		t.Fatal(err)
	}
	asked, released := permit.counts()
	if asked != 2 {
		t.Fatalf("the copy must retry once after the refusal and then stop asking, got %d asks", asked)
	}
	if released != 1 {
		t.Fatalf("the eventual grant must be released exactly once, got %d", released)
	}
	if grown := grownPermitReads(reader.sizes); grown == 0 {
		t.Fatal("a direction granted on the retry must switch to the enlarged buffer")
	}
}

func TestIncreaseBufferPermitReleasedOnWriteError(t *testing.T) {
	permit := &permitRecorder{}
	reader := &permitReader{remaining: 4 << 20}
	writer := &permitWriter{limit: 600 * 1000, onLimit: errors.New("write failed")}
	if _, err := CopyWithIncreateBufferPermit(writer, reader, DefaultIncreaseBufferAfter, DefaultBatchSize, permit.seam); err == nil {
		t.Fatal("the copy must report the write error")
	}
	asked, released := permit.counts()
	if asked != 1 || released != 1 {
		t.Fatalf("a write error after growth must release the permit exactly once: asked=%d released=%d", asked, released)
	}
}

func TestIncreaseBufferPermitReleasedOnReadError(t *testing.T) {
	permit := &permitRecorder{}
	reader := &permitReader{remaining: 4 << 20, readErr: errors.New("read failed")}
	// Permit the reader to fail right after the growth point: copy 600000 bytes and
	// then return the error.
	reader.remaining = 600 * 1000
	writer := &permitWriter{limit: -1}
	if _, err := CopyWithIncreateBufferPermit(writer, reader, DefaultIncreaseBufferAfter, DefaultBatchSize, permit.seam); err == nil {
		t.Fatal("the copy must report the read error")
	}
	asked, released := permit.counts()
	if asked != 1 || released != 1 {
		t.Fatalf("a read error after growth must release the permit exactly once: asked=%d released=%d", asked, released)
	}
}

func TestNilIncreaseBufferPermitKeepsTheOldBehaviour(t *testing.T) {
	reader := &permitReader{remaining: 2 << 20}
	writer := &permitWriter{limit: -1}
	copied, err := CopyWithIncreateBuffer(writer, reader, DefaultIncreaseBufferAfter, DefaultBatchSize)
	if err != nil {
		t.Fatal(err)
	}
	if copied != 2<<20 {
		t.Fatalf("copied %d bytes, expected %d", copied, 2<<20)
	}
	if grown := grownPermitReads(reader.sizes); grown == 0 {
		t.Fatal("without a seam the copy must grow exactly as before")
	}
}

// permitReadWaiter is a source that drives the ReadWaiter copy loop (the loop a real
// socket uses), which is a different growth point from the pooled fallback above.
type permitReadWaiter struct {
	reader  *permitReader
	options N.ReadWaitOptions
}

// Read makes the waiter a valid io.Reader for the entry point; the copy loop uses the
// ReadWaiter methods below instead.
func (w *permitReadWaiter) Read(p []byte) (int, error) {
	return w.reader.Read(p)
}

func (w *permitReadWaiter) InitializeReadWaiter(options N.ReadWaitOptions) bool {
	w.options = options
	return false
}

func (w *permitReadWaiter) WaitReadBuffer() (*buf.Buffer, error) {
	buffer := w.options.NewBuffer()
	n, err := w.reader.Read(buffer.FreeBytes())
	if n > 0 {
		buffer.Truncate(n)
		return buffer, nil
	}
	buffer.Release()
	return nil, err
}

func TestIncreaseBufferPermitOnTheReadWaiterPath(t *testing.T) {
	permit := &permitRecorder{}
	source := &permitReadWaiter{reader: &permitReader{remaining: 2 << 20}}
	writer := &permitWriter{limit: -1}
	_, err := CopyWithIncreateBufferPermit(writer, source, DefaultIncreaseBufferAfter, DefaultBatchSize, permit.seam)
	if err != nil {
		t.Fatal(err)
	}
	asked, released := permit.counts()
	if asked != 1 || released != 1 {
		t.Fatalf("the read-waiter growth point must ask once and release once: asked=%d released=%d", asked, released)
	}
	if grown := grownPermitReads(source.reader.sizes); grown == 0 {
		t.Fatal("the read-waiter path must switch to the enlarged buffer on a grant")
	}
}
