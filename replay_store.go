package genotp

import (
	"sync"
	"time"
)

type ReplayStore interface {
	CheckAndRecord(key []byte, ttl time.Duration) (firstSeen bool, err error)
	Reset() error
}

type InMemoryReplayStore struct {
	mu         sync.Mutex
	entries    map[string]int64
	order      []string // insertion order for LRU eviction
	maxSize    int
	nextSweep  time.Time
	sweepEvery time.Duration
}

func NewInMemoryReplayStore(maxSize int) *InMemoryReplayStore {
	return &InMemoryReplayStore{
		entries:    make(map[string]int64),
		order:      make([]string, 0, maxSize),
		maxSize:    maxSize,
		sweepEvery: 30 * time.Second,
	}
}

func (s *InMemoryReplayStore) CheckAndRecord(key []byte, ttl time.Duration) (bool, error) {
	now := time.Now()
	nowNano := now.UnixNano()
	expireAt := nowNano + ttl.Nanoseconds()

	s.mu.Lock()
	defer s.mu.Unlock()

	if now.After(s.nextSweep) {
		s.sweepExpiredLocked(nowNano)
		s.nextSweep = now.Add(s.sweepEvery)
	}

	keyStr := string(key)
	if exp, ok := s.entries[keyStr]; ok && exp > nowNano {
		return false, nil
	}

	if len(s.entries) >= s.maxSize {
		s.sweepExpiredLocked(nowNano)
		if len(s.entries) >= s.maxSize {
			s.evictBatchLocked()
		}
	}

	// If key already existed (expired, now being re-recorded), remove from order slice
	if _, existed := s.entries[keyStr]; existed {
		s.removeFromOrderLocked(keyStr)
	}

	s.entries[keyStr] = expireAt
	s.order = append(s.order, keyStr)
	return true, nil
}

func (s *InMemoryReplayStore) removeFromOrderLocked(key string) {
	for i, k := range s.order {
		if k == key {
			s.order = append(s.order[:i], s.order[i+1:]...)
			return
		}
	}
}

func (s *InMemoryReplayStore) sweepExpiredLocked(nowNano int64) {
	// Rebuild order in a single O(N) pass instead of calling
	// removeFromOrderLocked per expired entry (which would be O(N^2)).
	// Safe to reuse s.order's backing array: each iteration reads s.order[i]
	// into k before append writes to position len(newOrder) <= i.
	newOrder := s.order[:0]
	for _, k := range s.order {
		exp, ok := s.entries[k]
		if !ok {
			continue
		}
		if exp <= nowNano {
			delete(s.entries, k)
			continue
		}
		newOrder = append(newOrder, k)
	}
	s.order = newOrder
}

func (s *InMemoryReplayStore) evictBatchLocked() {
	target := max(len(s.entries)/10, 1)
	count := 0
	for count < target && len(s.order) > 0 {
		oldest := s.order[0]
		s.order = s.order[1:]
		delete(s.entries, oldest)
		count++
	}
}

func (s *InMemoryReplayStore) Reset() error {
	s.mu.Lock()
	s.entries = make(map[string]int64)
	s.order = s.order[:0]
	s.nextSweep = time.Time{}
	s.mu.Unlock()
	return nil
}

func (s *InMemoryReplayStore) Size() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}
