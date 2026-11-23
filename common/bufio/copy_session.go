package bufio

import (
	"io"

	N "github.com/sagernet/sing/common/network"
)

// IncreaseBufferPermit decides, at the copy engine's real buffer-growth boundary,
// whether one copy direction may switch to the enlarged read buffer.
//
// It is called when the configured IncreaseBufferAfter threshold has been reached, not
// when the copy starts. A direction that never copies that many bytes is therefore never
// asked and never charges the caller's policy, which is the difference between "allowed
// to try to grow" and "holds an enlarged buffer".
//
// granted reports whether the copy loop should enlarge its read buffer now. release, if
// non-nil, is called exactly once when the outer copy function returns - on EOF, a read
// error, a write error and a handshake-restart loop alike - after the last enlarged
// buffer has been written, so a caller can hold a resource exactly while the enlarged
// buffer exists. A nil release is valid: an exempt direction may need no accounting.
//
// A refusal is not permanent: the copy loop re-asks only at a bounded milestone
// (max(IncreaseBufferAfter, 1 MiB) further bytes), so a direction that was refused under
// pressure can still grow when capacity frees up, without a decision or a lock on every
// read.
//
// A nil seam keeps the pre-existing behaviour: the switch happens unconditionally once
// the threshold is reached.
type IncreaseBufferPermit func() (release func(), granted bool)

type CopyOptions struct {
	ReadWaitOptions     N.ReadWaitOptions
	IncreaseBufferAfter int64
	// IncreaseBufferPermit optionally gates the switch to the enlarged buffer at the
	// growth boundary. Nil means unconditional growth, exactly as before this field
	// existed.
	IncreaseBufferPermit IncreaseBufferPermit
	ReadCounters         []N.CountFunc
	WriteCounters        []N.CountFunc
	Handshake            N.HandshakeState
}

// increaseBufferRetryStep is the minimum number of further bytes the copy loop copies
// before re-asking a seam that refused. It keeps a refusal from becoming a per-read
// callback at a small IncreaseBufferAfter (the geometry-required threshold is 1) while
// still letting a direction grow soon after capacity frees.
const increaseBufferRetryStep = 1 << 20

type CopySession struct {
	source       io.Reader
	destination  io.Writer
	originSource io.Reader
	options      CopyOptions
	onTransfer   func(n int64) error
	// increaseBufferRelease is non-nil exactly while this session holds the enlarged
	// buffer and a permit release is owed. It is set at most once and cleared exactly
	// once, on the copy's exit path.
	increaseBufferRelease func()
	// increaseBufferRetryAt is the copied-byte count at which a refused seam may be
	// asked again. It is only consulted after the configured threshold is reached, so
	// an unrefused copy never reads it.
	increaseBufferRetryAt int64
}

func NewCopySession(destination io.Writer, source io.Reader, originSource io.Reader, options CopyOptions) *CopySession {
	session := &CopySession{
		source:       source,
		destination:  destination,
		originSource: originSource,
		options:      options,
	}
	session.resetTransferHook()
	return session
}

func (s *CopySession) ResetHandshake() {
	s.options.Handshake = N.NewHandshakeState(s.source, s.destination)
	s.resetTransferHook()
}

func (s *CopySession) Transfer(n int64) error {
	if s.onTransfer == nil {
		return nil
	}
	return s.onTransfer(n)
}

func (s *CopySession) resetTransferHook() {
	s.onTransfer = newTransferHook(s.options.Handshake, s.options.ReadCounters, s.options.WriteCounters)
}

// tryIncreaseBuffer decides whether the copy loop should switch to the enlarged read
// buffer now, having copied n bytes.
//
// With no seam it answers true, which is exactly what the loop did before the seam
// existed. With a seam it asks only at the growth boundary and then only at bounded
// milestones after a refusal; a grant is remembered so no later call asks a second time
// and so only one release is stored.
func (s *CopySession) tryIncreaseBuffer(n int64) bool {
	if s.options.IncreaseBufferPermit == nil {
		return true
	}
	if s.increaseBufferRelease != nil {
		return true
	}
	if n < s.increaseBufferRetryAt {
		return false
	}
	release, granted := s.options.IncreaseBufferPermit()
	if !granted {
		retryAfter := s.options.IncreaseBufferAfter
		if retryAfter < increaseBufferRetryStep {
			retryAfter = increaseBufferRetryStep
		}
		s.increaseBufferRetryAt = n + retryAfter
		return false
	}
	s.increaseBufferRelease = release
	return true
}

// releaseIncreaseBufferPermit runs the seam's release exactly once. It is called by the
// outer copy function's defer, so every exit path (EOF, read error, write error,
// handshake restart) releases after the enlarged buffers are no longer in use. A nil
// release, as returned by an exempt caller, is a no-op.
func (s *CopySession) releaseIncreaseBufferPermit() {
	release := s.increaseBufferRelease
	if release == nil {
		return
	}
	s.increaseBufferRelease = nil
	release()
}

func newTransferHook(handshake N.HandshakeState, readCounters []N.CountFunc, writeCounters []N.CountFunc) func(n int64) error {
	upgradable := handshake.Upgradable()
	if len(readCounters) == 0 && len(writeCounters) == 0 && !upgradable {
		return nil
	}
	return func(n int64) error {
		for _, counter := range readCounters {
			counter(n)
		}
		for _, counter := range writeCounters {
			counter(n)
		}
		if upgradable {
			return handshake.Check()
		}
		return nil
	}
}
