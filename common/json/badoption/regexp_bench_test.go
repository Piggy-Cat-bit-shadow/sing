package badoption

import (
	"runtime"
	"strconv"
	"testing"

	"github.com/sagernet/sing/common/json"
)

var benchmarkSink any

// BenchmarkRegexpDecode measures a configuration decoding one regexp option per
// holder. "baseline" is the old data model, where every holder compiled its own
// object; "shared" decodes through the cache with a cold cache per iteration,
// which is the same unit of work. Sizes 1, 3, 10, 40 and 100 are covered in
// both shapes: all expressions distinct, and every holder naming the same
// expression.
func BenchmarkRegexpDecode(b *testing.B) {
	for _, size := range []int{1, 3, 10, 40, 100} {
		for _, distinct := range []bool{true, false} {
			mode := "duplicated"
			if distinct {
				mode = "distinct"
			}
			_, contents := measurementInputs(size, distinct)
			suffix := "/" + mode + "/" + strconv.Itoa(size)

			b.Run("baseline"+suffix, func(b *testing.B) {
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					options := make([]legacyRegexp, len(contents))
					for j, content := range contents {
						options[j] = decodeLegacy(content)
					}
					benchmarkSink = options
				}
			})
			b.Run("shared"+suffix, func(b *testing.B) {
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					resetSharedRegexpCache()
					options := make([]*Regexp, len(contents))
					for j, content := range contents {
						var option Regexp
						if err := json.Unmarshal(content, &option); err != nil {
							b.Fatal(err)
						}
						options[j] = &option
					}
					benchmarkSink = options
				}
			})
		}
	}
}

// BenchmarkRegexpReload is the realistic steady state on the shared path: a
// config reload decodes the same expressions again while the previous
// configuration is still alive, so every lookup is a hit. The baseline has no
// equivalent because it always recompiles.
func BenchmarkRegexpReload(b *testing.B) {
	const size = 10
	_, contents := measurementInputs(size, false)

	b.Run("baseline/duplicated/10", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			options := make([]legacyRegexp, len(contents))
			for j, content := range contents {
				options[j] = decodeLegacy(content)
			}
			benchmarkSink = options
		}
	})

	b.Run("shared/duplicated/10", func(b *testing.B) {
		holders := make([]*Regexp, len(contents))
		for i, content := range contents {
			holders[i] = new(Regexp)
			if err := json.Unmarshal(content, holders[i]); err != nil {
				b.Fatal(err)
			}
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			options := make([]*Regexp, len(contents))
			for j, content := range contents {
				var option Regexp
				if err := json.Unmarshal(content, &option); err != nil {
					b.Fatal(err)
				}
				options[j] = &option
			}
			benchmarkSink = options
		}
		b.StopTimer()
		runtime.KeepAlive(holders)
	})
}

// BenchmarkRegexpBuild measures the safety copy: Build must not expose the
// shared object because Longest mutates it, so each call allocates one
// regexp.Regexp shell while reusing the compiled program.
func BenchmarkRegexpBuild(b *testing.B) {
	option, err := NewRegexp(`^bench-(hk|sg)-\d+$`)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchmarkSink = option.Build()
	}
}
