package badoption

import (
	"fmt"
	"math/rand"
	"regexp"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing/common/json"
	"github.com/stretchr/testify/require"
)

// Test helpers. The cache and the compile function are package internals, and
// the tests need to observe both: the compile counter is the only direct proof
// that two options share one parse, and the entry helpers are needed to drive
// the ABA case deterministically.

func resetSharedRegexpCache() {
	regexpCacheMu.Lock()
	regexpCache = make(map[string]*regexpCacheEntry)
	regexpCacheMu.Unlock()
}

func sharedRegexpCacheLen() int {
	regexpCacheMu.Lock()
	defer regexpCacheMu.Unlock()
	return len(regexpCache)
}

func sharedRegexpCacheEntry(expression string) *regexpCacheEntry {
	regexpCacheMu.Lock()
	defer regexpCacheMu.Unlock()
	return regexpCache[expression]
}

func deleteSharedRegexpCacheEntry(expression string) {
	regexpCacheMu.Lock()
	delete(regexpCache, expression)
	regexpCacheMu.Unlock()
}

type regexpCompileCounter struct {
	count    atomic.Int64
	previous func(string) (*regexp.Regexp, error)
}

func installRegexpCompileCounter(t *testing.T) *regexpCompileCounter {
	t.Helper()
	counter := &regexpCompileCounter{previous: compileRegexp}
	compileRegexp = func(expression string) (*regexp.Regexp, error) {
		counter.count.Add(1)
		return counter.previous(expression)
	}
	t.Cleanup(func() {
		compileRegexp = counter.previous
	})
	return counter
}

func (c *regexpCompileCounter) total() int64 {
	return c.count.Load()
}

func jsonString(t *testing.T, expression string) []byte {
	t.Helper()
	content, err := json.Marshal(expression)
	require.NoError(t, err)
	return content
}

func decodeRegexp(t *testing.T, expression string) *Regexp {
	t.Helper()
	var option Regexp
	require.NoError(t, json.Unmarshal(jsonString(t, expression), &option))
	return &option
}

func heapAllocAfterGC() uint64 {
	runtime.GC()
	runtime.GC()
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	return stats.HeapAlloc
}

// TestRegexpSharesOneCompiledObject is the core sharing assertion: every option
// decoded from one expression must point at the same compiled object, and a
// different expression must not reuse it. The compile counter makes the test
// fail if a second parse happens for the same key, even if the test were to
// compare only behaviour.
func TestRegexpSharesOneCompiledObject(t *testing.T) {
	resetSharedRegexpCache()
	counter := installRegexpCompileCounter(t)

	const expression = `^prov-(hk|sg)-\d+$`
	const holders = 64
	options := make([]*Regexp, 0, holders)
	for i := 0; i < holders; i++ {
		options = append(options, decodeRegexp(t, expression))
	}
	require.EqualValues(t, 1, counter.total(), "the same expression must be compiled once")

	canonical := options[0].compiled
	require.NotNil(t, canonical)
	for i, option := range options {
		require.Same(t, canonical, option.compiled, "holder %d has a different compiled object", i)
	}

	// The programmatic constructor must join the same shared object as JSON
	// decoding; it is not a second, private compile path.
	constructed, err := NewRegexp(expression)
	require.NoError(t, err)
	require.Same(t, canonical, constructed.compiled)
	require.EqualValues(t, 1, counter.total())

	// Build must not hand out the canonical object itself: Longest would
	// otherwise mutate state shared by every holder.
	built := options[0].Build()
	require.NotNil(t, built)
	require.NotSame(t, built, options[1].Build())
	require.NotSame(t, built, canonical)
	require.Equal(t, expression, built.String())
	require.True(t, built.MatchString("prov-hk-01"))

	// A different expression must be a different object with different
	// behaviour, not a cache hit on the first one.
	other := decodeRegexp(t, `^prov-(hk|sg)-\d+$ `)
	require.NotSame(t, canonical, other.compiled)
	require.EqualValues(t, 2, counter.total())
	require.False(t, other.Build().MatchString("prov-hk-01"))
}

// TestRegexpSemanticsNotMixed covers expressions that are textually close but
// mean different things.
func TestRegexpSemanticsNotMixed(t *testing.T) {
	resetSharedRegexpCache()
	counter := installRegexpCompileCounter(t)

	caseSensitive := decodeRegexp(t, `hk`)
	caseInsensitive := decodeRegexp(t, `(?i)hk`)
	literalDot := decodeRegexp(t, `a\.b`)
	anyDot := decodeRegexp(t, `a.b`)
	anchored := decodeRegexp(t, `^hk$`)
	unanchored := decodeRegexp(t, `hk`)

	require.NotSame(t, caseSensitive.compiled, caseInsensitive.compiled)
	require.NotSame(t, literalDot.compiled, anyDot.compiled)
	require.NotSame(t, anchored.compiled, unanchored.compiled)
	require.EqualValues(t, 5, counter.total())

	require.True(t, caseSensitive.Build().MatchString("hk"))
	require.False(t, caseSensitive.Build().MatchString("HK"))
	require.True(t, caseInsensitive.Build().MatchString("HK"))
	require.True(t, literalDot.Build().MatchString("a.b"))
	require.False(t, literalDot.Build().MatchString("axb"))
	require.True(t, anyDot.Build().MatchString("axb"))
	require.True(t, anyDot.Build().MatchString("a.b"))
	require.False(t, anyDot.Build().MatchString("ab"))
	require.True(t, anchored.Build().MatchString("hk"))
	require.False(t, anchored.Build().MatchString("hk-01"))
	require.True(t, unanchored.Build().MatchString("hk-01"))
}

// TestRegexpMatchesStdlib compares every shared object with a direct
// regexp.Compile of the same text, including Unicode, case handling, the empty
// pattern and the error text for invalid patterns.
func TestRegexpMatchesStdlib(t *testing.T) {
	resetSharedRegexpCache()

	testCases := []struct {
		name       string
		expression string
		inputs     []string
	}{
		{"empty pattern", "", []string{"", "anything"}},
		{"include prefix", `^prov/(hk|sg)-\d+$`, []string{"prov/hk-01", "prov/sg-02", "prov/us-01", "xprov/hk-01"}},
		{"case sensitive", `hk`, []string{"hk", "HK", "Hk"}},
		{"case insensitive", `(?i)hk`, []string{"hk", "HK", "Hk"}},
		{"unicode class", `\p{Han}+`, []string{"节点-01", "node-01", "mixed 节 node"}},
		{"unicode rune", `^.$`, []string{"界", "ab", ""}},
		{"alternation", `a|ab`, []string{"ab", "a", "b"}},
		{"anchored", `^\d{2,4}$`, []string{"7", "42", "1234", "12345"}},
		{"escaped dot", `^a\.b$`, []string{"a.b", "axb"}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			reference, err := regexp.Compile(testCase.expression)
			require.NoError(t, err)
			option := decodeRegexp(t, testCase.expression)
			built := option.Build()
			require.Equal(t, reference.String(), built.String())
			for _, input := range testCase.inputs {
				require.Equal(t, reference.FindStringIndex(input), built.FindStringIndex(input), "input %q", input)
				require.Equal(t, reference.MatchString(input), built.MatchString(input), "input %q", input)
			}
		})
	}
}

// TestRegexpInvalidPattern proves invalid patterns still fail at the decode
// entry point with regexp.Compile's error, and that a failure is not cached as
// an empty success.
func TestRegexpInvalidPattern(t *testing.T) {
	resetSharedRegexpCache()
	counter := installRegexpCompileCounter(t)

	for _, expression := range []string{"(", "[", `\`, "*", "(?P<)", `a{2,1}`} {
		_, referenceErr := regexp.Compile(expression)
		require.Error(t, referenceErr)
		content := jsonString(t, expression)

		var option Regexp
		err := json.Unmarshal(content, &option)
		require.EqualError(t, err, referenceErr.Error(), "expression %q", expression)
		require.Nil(t, option.compiled)
		require.Nil(t, option.Build())
		require.Nil(t, sharedRegexpCacheEntry(expression), "invalid expression must not be cached")

		// A second attempt must fail the same way instead of hitting a cached
		// empty success.
		var retry Regexp
		require.EqualError(t, json.Unmarshal(content, &retry), referenceErr.Error())

		constructed, err := NewRegexp(expression)
		require.Nil(t, constructed)
		require.EqualError(t, err, referenceErr.Error())
	}
	require.EqualValues(t, 18, counter.total())
	require.Zero(t, sharedRegexpCacheLen())

	// A valid expression still works after the failures.
	valid := decodeRegexp(t, `^ok-\d+$`)
	require.True(t, valid.Build().MatchString("ok-1"))
}

// TestRegexpJSONFormat pins the wire format: a regex is a JSON string, an empty
// pattern stays an empty pattern, and the historical null handling (decode as
// the empty expression) is unchanged.
func TestRegexpJSONFormat(t *testing.T) {
	resetSharedRegexpCache()

	type options struct {
		Include *Regexp `json:"include,omitempty"`
		Exclude *Regexp `json:"exclude,omitempty"`
	}

	var decoded options
	require.NoError(t, json.Unmarshal([]byte(`{"include":"^hk-\\d+$","exclude":"(?i)expired"}`), &decoded))
	require.NotNil(t, decoded.Include)
	require.NotNil(t, decoded.Exclude)
	require.Equal(t, `^hk-\d+$`, decoded.Include.Build().String())
	require.Equal(t, `(?i)expired`, decoded.Exclude.Build().String())

	encoded, err := json.Marshal(decoded)
	require.NoError(t, err)
	require.JSONEq(t, `{"include":"^hk-\\d+$","exclude":"(?i)expired"}`, string(encoded))

	var empty options
	require.NoError(t, json.Unmarshal([]byte(`{"include":"","exclude":null}`), &empty))
	require.NotNil(t, empty.Include)
	require.Nil(t, empty.Exclude)
	require.NotNil(t, empty.Include.Build())
	require.True(t, empty.Include.Build().MatchString("anything"), "the empty pattern matches everything")
	encoded, err = json.Marshal(empty)
	require.NoError(t, err)
	require.JSONEq(t, `{"include":""}`, string(encoded))

	// Historical behaviour: null decoded into a value (not a pointer field)
	// ran UnmarshalJSON with "null", which decodes as the empty expression.
	var nullValue Regexp
	require.NoError(t, json.Unmarshal([]byte("null"), &nullValue))
	require.NotNil(t, nullValue.compiled)
	require.Equal(t, "", nullValue.Build().String())
	encoded, err = json.Marshal(&nullValue)
	require.NoError(t, err)
	require.Equal(t, `""`, string(encoded))

	// The zero value marshals to the empty string, as the zero regexp did.
	// (As before, the marshaller is on the pointer receiver, which is the only
	// form the option structs use.)
	encoded, err = json.Marshal(&Regexp{})
	require.NoError(t, err)
	require.Equal(t, `""`, string(encoded))

	// A nil pointer field is omitted, as before.
	encoded, err = json.Marshal(options{})
	require.NoError(t, err)
	require.JSONEq(t, `{}`, string(encoded))
}

// TestRegexpLongestIsolation covers the mutation hazard that forces Build to
// copy: Longest on one holder must never change another holder or a later
// Build of the same option.
func TestRegexpLongestIsolation(t *testing.T) {
	resetSharedRegexpCache()
	counter := installRegexpCompileCounter(t)

	const expression = `a|ab`
	first := decodeRegexp(t, expression)
	second := decodeRegexp(t, expression)
	require.Same(t, first.compiled, second.compiled)
	require.EqualValues(t, 1, counter.total())

	firstBuilt := first.Build()
	firstBuilt.Longest()
	require.Equal(t, "ab", firstBuilt.FindString("ab"), "Longest must apply to the object it was called on")
	require.Equal(t, "a", second.Build().FindString("ab"), "Longest must not leak to another holder")
	require.Equal(t, "a", first.Build().FindString("ab"), "Longest must not leak through the option")
	require.EqualValues(t, 1, counter.total())
}

// TestRegexpIncludeExcludePrecedence runs the exact filter expression used by
// the parent's policy groups and remote providers, against both shared and
// directly compiled matchers. Exclude wins over include; a missing filter is
// nil and matches everything.
func TestRegexpIncludeExcludePrecedence(t *testing.T) {
	resetSharedRegexpCache()
	counter := installRegexpCompileCounter(t)

	include := decodeRegexp(t, `^prov/(hk|sg)-`)
	exclude := decodeRegexp(t, `-expired$`)
	// A second configuration names the same two expressions; it must reuse the
	// same compiled objects rather than parse them again.
	otherInclude := decodeRegexp(t, `^prov/(hk|sg)-`)
	otherExclude := decodeRegexp(t, `-expired$`)
	require.Same(t, include.compiled, otherInclude.compiled)
	require.Same(t, exclude.compiled, otherExclude.compiled)
	require.EqualValues(t, 2, counter.total())

	referenceInclude, err := regexp.Compile(`^prov/(hk|sg)-`)
	require.NoError(t, err)
	referenceExclude, err := regexp.Compile(`-expired$`)
	require.NoError(t, err)

	tags := []string{"prov/hk-01", "prov/hk-expired", "prov/sg-02", "prov/sg-expired", "prov/us-01", "self"}

	filterLoop := func(excludeMatcher *regexp.Regexp, includeMatcher *regexp.Regexp) []string {
		var kept []string
		for _, tag := range tags {
			if excludeMatcher != nil && excludeMatcher.MatchString(tag) {
				continue
			}
			if includeMatcher != nil && !includeMatcher.MatchString(tag) {
				continue
			}
			kept = append(kept, tag)
		}
		return kept
	}
	filterBoolean := func(excludeMatcher *regexp.Regexp, includeMatcher *regexp.Regexp) []string {
		var kept []string
		for _, tag := range tags {
			if (excludeMatcher == nil || !excludeMatcher.MatchString(tag)) &&
				(includeMatcher == nil || includeMatcher.MatchString(tag)) {
				kept = append(kept, tag)
			}
		}
		return kept
	}

	expected := filterLoop(referenceExclude, referenceInclude)
	require.Equal(t, []string{"prov/hk-01", "prov/sg-02"}, expected)
	require.Equal(t, expected, filterLoop(exclude.Build(), include.Build()))
	require.Equal(t, expected, filterBoolean(otherExclude.Build(), otherInclude.Build()))

	require.Equal(t, []string{"prov/hk-01", "prov/hk-expired", "prov/sg-02", "prov/sg-expired"}, filterLoop(nil, include.Build()))
	require.Equal(t, []string{"prov/hk-01", "prov/sg-02", "prov/us-01", "self"}, filterLoop(exclude.Build(), nil))
	require.Equal(t, tags, filterLoop(nil, nil))

	// Build works on nil options too, matching the old nil conversion.
	var nilOption *Regexp
	require.Nil(t, nilOption.Build())
}

// TestRegexpConcurrentParseAndMatch exercises the locking in both directions:
// concurrent decodes of the same expression must compile once, and matching on
// copies must stay correct while other goroutines copy the same canonical
// object.
func TestRegexpConcurrentParseAndMatch(t *testing.T) {
	resetSharedRegexpCache()
	counter := installRegexpCompileCounter(t)

	expressions := []string{
		`^worker-(hk|sg)-\d+$`,
		`^worker-(jp|us)-\d+$`,
		`(?i)^WORKER-HK-\d+$`,
		`^worker-\p{Han}-\d+$`,
		`^worker-.*-0[0-9]$`,
	}
	inputs := []string{"worker-hk-1", "worker-jp-22", "WORKER-HK-7", "worker-节点-9", "worker-x-42", "nomatch"}
	references := make([]*regexp.Regexp, len(expressions))
	for i, expression := range expressions {
		reference, err := regexp.Compile(expression)
		require.NoError(t, err)
		references[i] = reference
	}
	contents := make([][]byte, len(expressions))
	for i, expression := range expressions {
		contents[i] = jsonString(t, expression)
	}

	// Hold one option per expression for the duration of the test: this keeps
	// the canonical objects alive so the workers observe cache hits rather than
	// racing a legitimate cleanup after a garbage collection.
	holders := make([]*Regexp, len(expressions))
	for i, content := range contents {
		holders[i] = new(Regexp)
		require.NoError(t, json.Unmarshal(content, holders[i]))
	}
	require.EqualValues(t, len(expressions), counter.total())

	var waitGroup sync.WaitGroup
	for worker := 0; worker < 16; worker++ {
		waitGroup.Add(1)
		go func(worker int) {
			defer waitGroup.Done()
			for iteration := 0; iteration < 100; iteration++ {
				index := (worker + iteration) % len(expressions)
				var option Regexp
				if err := json.Unmarshal(contents[index], &option); err != nil {
					t.Errorf("worker %d: decode: %v", worker, err)
					return
				}
				built := option.Build()
				for _, input := range inputs {
					got := built.FindStringIndex(input)
					want := references[index].FindStringIndex(input)
					if len(got) != len(want) || (len(got) == 2 && (got[0] != want[0] || got[1] != want[1])) {
						t.Errorf("worker %d: %q against %q: got %v, want %v", worker, input, expressions[index], got, want)
						return
					}
				}
			}
		}(worker)
	}
	waitGroup.Wait()
	runtime.KeepAlive(holders)

	require.EqualValues(t, len(expressions), counter.total(), "concurrent decodes must not compile a key twice")
	require.Equal(t, len(expressions), sharedRegexpCacheLen())
}

// TestRegexpReloadAndRelease covers two lifetimes at once: a matcher built from
// an option keeps matching after the configuration is gone, and a later reload
// of the same expression is correct even if the old canonical object has been
// reclaimed in between.
func TestRegexpReloadAndRelease(t *testing.T) {
	resetSharedRegexpCache()
	counter := installRegexpCompileCounter(t)

	const expression = `^reload-(hk|sg)-\d+$`
	config := decodeRegexp(t, expression)
	matcher := config.Build()
	config = nil

	require.EqualValues(t, 1, counter.total())
	require.True(t, matcher.MatchString("reload-hk-1"))
	require.True(t, matcher.MatchString("reload-sg-2"))

	// The matcher holds a copy that shares the compiled program but not the
	// canonical object, so the cache entry can be collected while the matcher
	// stays usable. Cleanup is asynchronous; poll it.
	require.Eventually(t, func() bool {
		runtime.GC()
		return sharedRegexpCacheLen() == 0
	}, 10*time.Second, 10*time.Millisecond, "released configuration should not stay in the cache")

	require.True(t, matcher.MatchString("reload-hk-1"), "match must stay correct after the old config was released")

	reloaded := decodeRegexp(t, expression)
	require.EqualValues(t, 2, counter.total(), "a reload after reclamation compiles the expression again")
	require.True(t, reloaded.Build().MatchString("reload-sg-2"))
	require.Equal(t, 1, sharedRegexpCacheLen())
}

// TestRegexpCacheABACleanup is the deterministic ABA case: the same key is
// rebuilt while the previous generation's cleanup is still pending, and that
// late cleanup must not remove the newer entry. The cleanup is invoked directly
// because the runtime gives no ordering guarantee between "object reclaimed"
// and "cleanup runs"; this is exactly the state a delayed cleanup observes.
func TestRegexpCacheABACleanup(t *testing.T) {
	resetSharedRegexpCache()
	counter := installRegexpCompileCounter(t)

	const expression = `^aba-(hk|sg)-\d+$`
	oldOption := decodeRegexp(t, expression)
	oldEntry := sharedRegexpCacheEntry(expression)
	require.NotNil(t, oldEntry)
	require.Same(t, oldOption.compiled, oldEntry.compiled.Value())
	require.EqualValues(t, 1, counter.total())

	// Simulate the cache losing the old generation before its cleanup runs:
	// delete the slot without touching the entry, then rebuild the key.
	deleteSharedRegexpCacheEntry(expression)
	require.Nil(t, sharedRegexpCacheEntry(expression))

	newOption := decodeRegexp(t, expression)
	newEntry := sharedRegexpCacheEntry(expression)
	require.NotNil(t, newEntry)
	require.NotSame(t, oldEntry, newEntry)
	require.EqualValues(t, 2, counter.total())
	require.Same(t, newOption.compiled, newEntry.compiled.Value())

	// The old generation's cleanup runs late. It must leave the newer entry
	// alone, and it must be safe to run more than once.
	oldEntry.remove()
	require.Same(t, newEntry, sharedRegexpCacheEntry(expression), "a late cleanup removed the newer generation")
	oldEntry.remove()
	require.Same(t, newEntry, sharedRegexpCacheEntry(expression))

	// The newer generation is still the cache's answer.
	nextOption := decodeRegexp(t, expression)
	require.Same(t, newOption.compiled, nextOption.compiled)
	require.EqualValues(t, 2, counter.total())
}

// TestRegexpCacheBounded proves that unique expressions do not accumulate in
// the cache once their options are gone: each round parses a fresh set, drops
// it, and requires the entry count to fall back to zero. Live heap is measured
// as well, but the entry count is the strict assertion because the map is what
// must not grow without bound.
func TestRegexpCacheBounded(t *testing.T) {
	const (
		rounds   = 3
		perRound = 200
	)
	resetSharedRegexpCache()
	counter := installRegexpCompileCounter(t)

	// A deterministic PRNG keeps the test reproducible while the expressions
	// are random; the round and index make every one of them unique.
	random := rand.New(rand.NewSource(1))
	initialHeap := heapAllocAfterGC()
	var heaps []uint64
	for round := 0; round < rounds; round++ {
		func() {
			held := make([]*Regexp, 0, perRound)
			for i := 0; i < perRound; i++ {
				var suffix [12]byte
				for j := range suffix {
					suffix[j] = byte('a' + random.Intn(26))
				}
				expression := fmt.Sprintf(`^round-%d-node-%03d-%s$`, round, i, suffix)
				option, err := NewRegexp(expression)
				require.NoError(t, err)
				held = append(held, option)
			}
			require.Equal(t, perRound, sharedRegexpCacheLen())
		}()
		require.Eventually(t, func() bool {
			runtime.GC()
			return sharedRegexpCacheLen() == 0
		}, 15*time.Second, 20*time.Millisecond, "round %d: cache entries outlived their options", round)
		heaps = append(heaps, heapAllocAfterGC())
	}
	runtime.KeepAlive(counter)
	require.EqualValues(t, rounds*perRound, counter.total())

	t.Logf("cache entries after every round: 0; live heap: initial %d bytes, rounds %v", initialHeap, heaps)
	require.Less(t, heaps[len(heaps)-1], initialHeap+16<<20, "live heap grew across dropped rounds")
}

// TestRegexpSharingMeasurement reports the cost model required for this change:
// compilation count, allocations and live heap for input sets with and without
// sharing, at 1, 3 (the small case), 10, 40 and 100 expressions, each both
// distinct and fully duplicated. Counts and duplicates are asserted; the heap
// and allocation figures are logged as the evidence for the report.
func TestRegexpSharingMeasurement(t *testing.T) {
	resetSharedRegexpCache()
	counter := installRegexpCompileCounter(t)

	for _, size := range []int{1, 3, 10, 40, 100} {
		for _, distinct := range []bool{true, false} {
			expressions, contents := measurementInputs(size, distinct)
			mode := "duplicated"
			if distinct {
				mode = "distinct"
			}

			// Compilation count, no sharing.
			counter.count.Store(0)
			baselineOptions := make([]legacyRegexp, len(contents))
			for i, content := range contents {
				baselineOptions[i] = decodeLegacy(content)
			}
			baselineCompiles := counter.total()
			runtime.KeepAlive(baselineOptions)

			// Compilation count, sharing.
			resetSharedRegexpCache()
			counter.count.Store(0)
			sharedOptions := make([]*Regexp, len(contents))
			for i, content := range contents {
				var option Regexp
				require.NoError(t, json.Unmarshal(content, &option))
				sharedOptions[i] = &option
			}
			sharedCompiles := counter.total()
			runtime.KeepAlive(sharedOptions)

			// Allocations per input set, cold cache for the shared path, which
			// is the comparable shape: the baseline has no cache at all.
			baselineAllocs := testing.AllocsPerRun(5, func() {
				options := make([]legacyRegexp, len(contents))
				for i, content := range contents {
					options[i] = decodeLegacy(content)
				}
				measurementSink = options
			})
			sharedAllocs := testing.AllocsPerRun(5, func() {
				resetSharedRegexpCache()
				options := make([]*Regexp, len(contents))
				for i, content := range contents {
					var option Regexp
					if err := json.Unmarshal(content, &option); err != nil {
						t.Fatalf("%s/%d: %v", mode, size, err)
					}
					options[i] = &option
				}
				measurementSink = options
			})
			// Build is the safety copy the parent must make once per runtime
			// matcher; report its allocation cost separately.
			buildAllocs := testing.AllocsPerRun(5, func() {
				measurementSink = sharedOptions[0].Build()
			})

			baselineHeap := medianLiveHeap(t, 3, func() any {
				options := make([]legacyRegexp, len(contents))
				for i, content := range contents {
					options[i] = decodeLegacy(content)
				}
				return options
			})
			sharedHeap := medianLiveHeap(t, 3, func() any {
				options := make([]*Regexp, len(contents))
				for i, content := range contents {
					var option Regexp
					if err := json.Unmarshal(content, &option); err != nil {
						t.Fatalf("%s/%d: %v", mode, size, err)
					}
					options[i] = &option
				}
				return options
			})

			t.Logf("%-10s n=%-3d compiles=%d/%d allocs=%2.0f/%-2.0f build-allocs=%.0f live-heap=%d/%d bytes (baseline/shared, expressions=%d)",
				mode, size, baselineCompiles, sharedCompiles, baselineAllocs, sharedAllocs, buildAllocs, baselineHeap, sharedHeap, len(expressions))

			require.EqualValues(t, len(expressions), baselineCompiles)
			if distinct {
				require.EqualValues(t, size, sharedCompiles)
			} else {
				require.EqualValues(t, 1, sharedCompiles)
			}
			require.EqualValues(t, 1, buildAllocs)
			if !distinct && size > 1 {
				require.Less(t, sharedAllocs, baselineAllocs, "sharing must reduce allocations for duplicated expressions")
				require.Less(t, sharedHeap, baselineHeap, "sharing must reduce live heap for duplicated expressions")
			}
		}
	}
}

// legacyRegexp reproduces the old option layout: the parsed value owned a whole
// regexp.Regexp, so every configuration kept its own compiled object.
type legacyRegexp regexp.Regexp

func decodeLegacy(content []byte) legacyRegexp {
	var expression string
	if err := json.Unmarshal(content, &expression); err != nil {
		panic(err)
	}
	compiled, err := compileRegexp(expression)
	if err != nil {
		panic(err)
	}
	return legacyRegexp(*compiled)
}

func measurementInputs(size int, distinct bool) ([]string, [][]byte) {
	expressions := make([]string, size)
	contents := make([][]byte, size)
	for i := 0; i < size; i++ {
		if distinct {
			expressions[i] = fmt.Sprintf(`^measure-%03d-(hk|sg)-\d+$`, i)
		} else {
			expressions[i] = `^measure-shared-(hk|sg)-\d+$`
		}
		content, err := json.Marshal(expressions[i])
		if err != nil {
			panic(err)
		}
		contents[i] = content
	}
	return expressions, contents
}

// medianLiveHeap measures the live heap retained by one built input set. The
// runtime does not guarantee that a single post-GC reading is stable, so the
// median of a few samples is used.
func medianLiveHeap(t *testing.T, samples int, build func() any) int64 {
	t.Helper()
	values := make([]int64, samples)
	for i := range values {
		resetSharedRegexpCache()
		runtime.GC()
		runtime.GC()
		var before runtime.MemStats
		runtime.ReadMemStats(&before)
		held := build()
		runtime.GC()
		runtime.GC()
		var after runtime.MemStats
		runtime.ReadMemStats(&after)
		values[i] = int64(after.HeapAlloc) - int64(before.HeapAlloc)
		runtime.KeepAlive(held)
	}
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
	return values[len(values)/2]
}

var measurementSink any
