package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/signature"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

type OIDCReasoningEncryptedContentSanitize struct {
	initOnce    sync.Once
	cleanupOnce sync.Once
	mu          sync.RWMutex
	cache       map[string]time.Time
}

const (
	oidcReasoningEncryptedContentTTL           = 6 * time.Hour
	oidcReasoningEncryptedContentCleanupPeriod = 15 * time.Minute
)

func newOIDCReasoningEncryptedContentSanitize() *OIDCReasoningEncryptedContentSanitize {
	return &OIDCReasoningEncryptedContentSanitize{}
}

func (s *OIDCReasoningEncryptedContentSanitize) PreSanitize(ctx context.Context, provider string, body []byte) []byte {
	s.ensureCache()

	input := gjson.GetBytes(body, "input")
	if !input.Exists() || !input.IsArray() {
		return body
	}

	provider = strings.TrimSpace(provider)

	updated := body
	for index, item := range input.Array() {
		if strings.TrimSpace(item.Get("type").String()) != "reasoning" {
			continue
		}

		encryptedContentPath := fmt.Sprintf("input.%d.encrypted_content", index)
		encryptedContent := gjson.GetBytes(updated, encryptedContentPath)
		if !encryptedContent.Exists() {
			continue
		}

		hash, err := oidcReasoningEncryptedContentHash(encryptedContent)
		if err != nil {
			continue
		}
		if hash == "" || !s.hasHash(hash) {
			continue
		}

		next, err := sjson.DeleteBytes(updated, encryptedContentPath)
		if err != nil {
			helps.LogWithRequestID(ctx).Debugf("%s: failed to pre-drop cached reasoning encrypted_content at input[%d]: %v", provider, index, err)
			continue
		}
		updated = next

		itemID := strings.TrimSpace(gjson.GetBytes(updated, fmt.Sprintf("input.%d.id", index)).String())
		if itemID == "" {
			itemID = fmt.Sprintf("input[%d]", index)
		}
		helps.LogWithRequestID(ctx).Debugf("%s: pre-dropped cached reasoning encrypted_content at input[%d] item_id=%q", provider, index, itemID)
	}
	return updated
}

func (s *OIDCReasoningEncryptedContentSanitize) Sanitize(ctx context.Context, provider string, body []byte) []byte {
	s.ensureCache()

	input := gjson.GetBytes(body, "input")
	if !input.Exists() || !input.IsArray() {
		return body
	}

	provider = strings.TrimSpace(provider)

	updated := body
	for index, item := range input.Array() {
		if strings.TrimSpace(item.Get("type").String()) != "reasoning" {
			continue
		}

		encryptedContentPath := fmt.Sprintf("input.%d.encrypted_content", index)
		encryptedContent := gjson.GetBytes(updated, encryptedContentPath)
		if !encryptedContent.Exists() {
			continue
		}

		hash, err := oidcReasoningEncryptedContentHash(encryptedContent)
		if err != nil {
			continue
		}
		next, err := sjson.DeleteBytes(updated, encryptedContentPath)
		if err != nil {
			helps.LogWithRequestID(ctx).Debugf("%s: failed to drop invalid reasoning encrypted_content at input[%d]: %v", provider, index, err)
			continue
		}
		updated = next
		s.rememberHash(hash)

		itemID := strings.TrimSpace(gjson.GetBytes(updated, fmt.Sprintf("input.%d.id", index)).String())
		if itemID == "" {
			itemID = fmt.Sprintf("input[%d]", index)
		}
		helps.LogWithRequestID(ctx).Debugf("%s: dropped invalid reasoning encrypted_content at input[%d] item_id=%q", provider, index, itemID)
	}
	return updated
}

func (s *OIDCReasoningEncryptedContentSanitize) ensureCache() {
	s.initOnce.Do(func() {
		s.cache = make(map[string]time.Time)
	})
	s.cleanupOnce.Do(s.startCleanup)
}

func (s *OIDCReasoningEncryptedContentSanitize) startCleanup() {
	go func() {
		ticker := time.NewTicker(oidcReasoningEncryptedContentCleanupPeriod)
		defer ticker.Stop()
		for range ticker.C {
			s.purgeExpired()
		}
	}()
}

func (s *OIDCReasoningEncryptedContentSanitize) purgeExpired() {
	now := time.Now()

	s.mu.Lock()
	defer s.mu.Unlock()

	for hash, expireAt := range s.cache {
		if !expireAt.After(now) {
			delete(s.cache, hash)
		}
	}
}

func (s *OIDCReasoningEncryptedContentSanitize) hasHash(hash string) bool {
	if hash == "" {
		return false
	}

	now := time.Now()

	s.mu.RLock()
	expireAt, ok := s.cache[hash]
	s.mu.RUnlock()
	if !ok || !expireAt.After(now) {
		return false
	}
	return true
}

func (s *OIDCReasoningEncryptedContentSanitize) rememberHash(hash string) {
	if hash == "" {
		return
	}
	s.mu.Lock()
	s.cache[hash] = time.Now().Add(oidcReasoningEncryptedContentTTL)
	s.mu.Unlock()
}

func oidcReasoningEncryptedContentHash(encryptedContent gjson.Result) (string, error) {
	value := encryptedContent.Raw
	if encryptedContent.Type == gjson.String {
		rawSignature := encryptedContent.String()
		if rawSignature != strings.TrimSpace(rawSignature) {
			errMsg := "encrypted_content has leading or trailing whitespace"
			return "", fmt.Errorf(errMsg)
		} else if _, err := signature.InspectGPTReasoningSignature(rawSignature); err != nil {
			return "", err
		}
		value = encryptedContent.String()
	} else {
		return "", fmt.Errorf("encrypted_content must be a string, got %s", encryptedContent.Type.String())
	}
	if strings.TrimSpace(value) == "" {
		return "", nil
	}

	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:]), nil
}
