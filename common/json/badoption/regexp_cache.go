package badoption

import (
	"regexp"
	"runtime"
	"sync"
	"weak"
)

// compileRegexp is a variable so tests can count compilations. Compilation is
// the cost the cache exists to remove, and the count is the only direct
// evidence that two options share one parse.
var compileRegexp = regexp.Compile

// regexpCacheEntry is one generation of the canonical compiled form of an
// expression.
//
// The entry is what the cache holds strongly, and it points at the compiled
// object only weakly: an option holds the compiled object strongly, so the
// entry (and the expression key) live exactly as long as some option decoded
// from that expression. When the last option goes away, the cleanup attached to
// the compiled object removes the entry. Delayed cleanup is harmless: a lookup
// that finds a dead weak pointer simply compiles a replacement, and the late
// cleanup only deletes the entry if the map still holds this exact generation.
type regexpCacheEntry struct {
	expression string
	compiled   weak.Pointer[regexp.Regexp]
}

// The key is the expression alone. regexp.Compile has no other inputs, and
// Longest is not a compile input: it is a flag on the receiver that only
// matching reads. Cached objects are always in the default (non-longest) mode
// and are never handed out, so that flag cannot change underneath a holder;
// Build gives each caller a copy on which Longest means only what that caller
// asked for. A future entry point that compiled with different semantics (for
// example regexp.CompilePOSIX, whose only difference is longest=true) would
// have to add that bit to the key.
var (
	regexpCacheMu sync.Mutex
	regexpCache   = make(map[string]*regexpCacheEntry)
)

// sharedRegexp returns the canonical compiled form of expression, compiling it
// at most once while that form stays reachable.
//
// Compilation happens under the mutex. That keeps the one-object-per-expression
// guarantee even when configurations are decoded concurrently, and it costs
// nothing in the common case because a hit never compiles. Invalid expressions
// return the compile error and are not cached.
func sharedRegexp(expression string) (*regexp.Regexp, error) {
	regexpCacheMu.Lock()
	defer regexpCacheMu.Unlock()
	if entry, loaded := regexpCache[expression]; loaded {
		if compiled := entry.compiled.Value(); compiled != nil {
			return compiled, nil
		}
		// The previous generation was reclaimed but its cleanup has not run
		// yet. Replace it; the late cleanup compares entry identity and will
		// leave the replacement alone.
	}
	compiled, err := compileRegexp(expression)
	if err != nil {
		return nil, err
	}
	entry := &regexpCacheEntry{
		expression: expression,
		compiled:   weak.Make(compiled),
	}
	regexpCache[expression] = entry
	runtime.AddCleanup(compiled, (*regexpCacheEntry).remove, entry)
	return compiled, nil
}

// remove deletes the cache entry for this generation, if it is still the
// current one. The identity comparison is what makes a late cleanup unable to
// remove a newer object compiled for the same expression after this one died.
func (e *regexpCacheEntry) remove() {
	regexpCacheMu.Lock()
	if regexpCache[e.expression] == e {
		delete(regexpCache, e.expression)
	}
	regexpCacheMu.Unlock()
}
