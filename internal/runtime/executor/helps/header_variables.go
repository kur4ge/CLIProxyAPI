package helps

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	mrand "math/rand"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Character sets supported by the ${random:...} header variable.
const (
	randomCharsetAlnum = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	randomCharsetAlpha = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	randomCharsetNum   = "0123456789"
	randomCharsetHex   = "0123456789abcdef"
)

// RenderHeaderValue expands variable placeholders in an OIDC header value.
//
// Supported placeholders:
//   - ${random:<charset>:<length>} generates a random string. <charset> is one
//     of alnum, alpha, num, hex. When a session seed is provided, the result is
//     deterministic for that seed so the same session yields the same value;
//     otherwise it is truly random per call.
//   - ${date:<layout>} formats the current time using a Go time layout
//     (e.g. 20060102150405). The special layout "unix" yields a Unix timestamp
//     in seconds and "unixmilli" yields milliseconds.
//
// Unknown placeholders are left untouched.
func RenderHeaderValue(value, sessionSeed string) string {
	if !strings.Contains(value, "${") {
		return value
	}
	var b strings.Builder
	for i := 0; i < len(value); {
		if strings.HasPrefix(value[i:], "${") {
			end := strings.Index(value[i:], "}")
			if end >= 0 {
				expr := value[i+2 : i+end]
				if rendered, ok := renderHeaderExpr(expr, sessionSeed); ok {
					b.WriteString(rendered)
					i += end + 1
					continue
				}
			}
		}
		b.WriteByte(value[i])
		i++
	}
	return b.String()
}

func renderHeaderExpr(expr, sessionSeed string) (string, bool) {
	parts := strings.Split(expr, ":")
	switch strings.TrimSpace(parts[0]) {
	case "random":
		return renderRandom(parts, sessionSeed), true
	case "date":
		return renderDate(parts), true
	case "session_data":
		return renderSessionData(parts, sessionSeed), true
	case "session_input_tokens":
		in, _ := cachedSessionTokens(sessionSeed)
		return strconv.FormatInt(in, 10), true
	case "session_output_tokens":
		_, out := cachedSessionTokens(sessionSeed)
		return strconv.FormatInt(out, 10), true
	default:
		return "", false
	}
}

func renderRandom(parts []string, sessionSeed string) string {
	charset := randomCharsetAlnum
	length := 16
	if len(parts) > 1 {
		switch strings.TrimSpace(parts[1]) {
		case "alnum", "":
			charset = randomCharsetAlnum
		case "alpha":
			charset = randomCharsetAlpha
		case "num":
			charset = randomCharsetNum
		case "hex":
			charset = randomCharsetHex
		default:
			charset = randomCharsetAlnum
		}
	}
	if len(parts) > 2 {
		if n, err := strconv.Atoi(strings.TrimSpace(parts[2])); err == nil && n > 0 {
			length = n
		}
	}

	rng := randomSource(sessionSeed)
	out := make([]byte, length)
	for i := range out {
		out[i] = charset[rng.Intn(len(charset))]
	}
	return string(out)
}

// randomSource returns a deterministic generator seeded by sessionSeed when it
// is present, otherwise a cryptographically seeded generator.
func randomSource(sessionSeed string) *mrand.Rand {
	if seed := strings.TrimSpace(sessionSeed); seed != "" {
		sum := sha256.Sum256([]byte(seed))
		return mrand.New(mrand.NewSource(int64(binary.BigEndian.Uint64(sum[:8]))))
	}
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return mrand.New(mrand.NewSource(time.Now().UnixNano()))
	}
	return mrand.New(mrand.NewSource(int64(binary.BigEndian.Uint64(buf[:]))))
}

func renderDate(parts []string) string {
	layout := time.RFC3339
	if len(parts) > 1 {
		// Rejoin remaining parts because Go layouts may contain colons (e.g. 15:04:05).
		layout = strings.TrimSpace(strings.Join(parts[1:], ":"))
	}
	return formatTime(time.Now(), layout)
}

// renderSessionData formats the timestamp of when the current session was first
// seen. The value is cached per session seed for one hour, and the TTL is reset
// on every access so an active session keeps the same start time. When no
// session seed is present the current time is used (cannot be correlated).
func renderSessionData(parts []string, sessionSeed string) string {
	layout := time.RFC3339
	if len(parts) > 1 {
		layout = strings.TrimSpace(strings.Join(parts[1:], ":"))
	}
	first := cachedSessionStart(sessionSeed)
	return formatTime(first, layout)
}

func formatTime(t time.Time, layout string) string {
	switch layout {
	case "":
		return t.Format(time.RFC3339)
	case "unix":
		return strconv.FormatInt(t.Unix(), 10)
	case "unixmilli":
		return strconv.FormatInt(t.UnixMilli(), 10)
	default:
		return t.Format(layout)
	}
}

type sessionStartCacheEntry struct {
	start        time.Time
	expire       time.Time
	inputTokens  int64
	outputTokens int64
}

var (
	sessionStartCache            = make(map[string]sessionStartCacheEntry)
	sessionStartCacheMu          sync.Mutex
	sessionStartCacheCleanupOnce sync.Once
)

const (
	sessionStartTTL                = time.Hour
	sessionStartCacheCleanupPeriod = 15 * time.Minute
)

func startSessionStartCacheCleanup() {
	go func() {
		ticker := time.NewTicker(sessionStartCacheCleanupPeriod)
		defer ticker.Stop()
		for range ticker.C {
			now := time.Now()
			sessionStartCacheMu.Lock()
			for key, entry := range sessionStartCache {
				if !entry.expire.After(now) {
					delete(sessionStartCache, key)
				}
			}
			sessionStartCacheMu.Unlock()
		}
	}()
}

// cachedSessionStart returns the time the session was first observed, refreshing
// the cache TTL on each call. Without a seed it returns the current time.
func cachedSessionStart(sessionSeed string) time.Time {
	seed := strings.TrimSpace(sessionSeed)
	now := time.Now()
	if seed == "" {
		return now
	}

	sessionStartCacheCleanupOnce.Do(startSessionStartCacheCleanup)
	key := sessionStartCacheKey(seed)

	sessionStartCacheMu.Lock()
	defer sessionStartCacheMu.Unlock()
	entry := touchSessionEntryLocked(key, now)
	return entry.start
}

// cachedSessionTokens returns the accumulated input/output tokens recorded for
// the session so far, refreshing the cache TTL. Without a seed it returns zero.
func cachedSessionTokens(sessionSeed string) (int64, int64) {
	seed := strings.TrimSpace(sessionSeed)
	if seed == "" {
		return 0, 0
	}

	sessionStartCacheCleanupOnce.Do(startSessionStartCacheCleanup)
	key := sessionStartCacheKey(seed)

	sessionStartCacheMu.Lock()
	defer sessionStartCacheMu.Unlock()
	entry := touchSessionEntryLocked(key, time.Now())
	return entry.inputTokens, entry.outputTokens
}

// AddSessionTokens accumulates the input/output tokens consumed by a request
// into the session cache so subsequent requests can expose the running totals
// via the ${session_input_tokens}/${session_output_tokens} header variables.
// The cache TTL is refreshed on each call. Calls without a seed are ignored.
func AddSessionTokens(sessionSeed string, inputTokens, outputTokens int64) {
	seed := strings.TrimSpace(sessionSeed)
	if seed == "" || (inputTokens == 0 && outputTokens == 0) {
		return
	}

	sessionStartCacheCleanupOnce.Do(startSessionStartCacheCleanup)
	key := sessionStartCacheKey(seed)

	sessionStartCacheMu.Lock()
	defer sessionStartCacheMu.Unlock()
	entry := touchSessionEntryLocked(key, time.Now())
	entry.inputTokens += inputTokens
	entry.outputTokens += outputTokens
	sessionStartCache[key] = entry
}

func sessionStartCacheKey(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	return hex.EncodeToString(sum[:])
}

// MarkSessionSeen reports whether this is the first time the session is observed
// (cache miss) and atomically records it so subsequent calls return false. The
// cache TTL is refreshed on every call. Sessions without a seed are always
// treated as first requests (they cannot be correlated across requests).
func MarkSessionSeen(sessionSeed string) bool {
	seed := strings.TrimSpace(sessionSeed)
	if seed == "" {
		return true
	}

	sessionStartCacheCleanupOnce.Do(startSessionStartCacheCleanup)
	key := sessionStartCacheKey(seed)
	now := time.Now()

	sessionStartCacheMu.Lock()
	defer sessionStartCacheMu.Unlock()
	entry, ok := sessionStartCache[key]
	first := !ok || !entry.expire.After(now)
	touchSessionEntryLocked(key, now)
	return first
}

// touchSessionEntryLocked fetches the session entry (creating a fresh one when
// missing or expired), refreshes its TTL, persists it, and returns it. Callers
// must hold sessionStartCacheMu.
func touchSessionEntryLocked(key string, now time.Time) sessionStartCacheEntry {
	entry, ok := sessionStartCache[key]
	if !ok || !entry.expire.After(now) {
		entry = sessionStartCacheEntry{start: now}
	}
	entry.expire = now.Add(sessionStartTTL)
	sessionStartCache[key] = entry
	return entry
}
