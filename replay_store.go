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
	maxSize    int
	nextSweep  time.Time
	sweepEvery time.Duration
}

func NewInMemoryReplayStore(maxSize int) *InMemoryReplayStore {
	return &InMemoryReplayStore{
		entries:    make(map[string]int64),
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

	s.entries[keyStr] = expireAt
	return true, nil
}

func (s *InMemoryReplayStore) sweepExpiredLocked(nowNano int64) {
	for k, exp := range s.entries {
		if exp <= nowNano {
			delete(s.entries, k)
		}
	}
}

func (s *InMemoryReplayStore) evictBatchLocked() {
	target := max(len(s.entries)/10, 1)
	count := 0
	for k := range s.entries {
		delete(s.entries, k)
		count++
		if count >= target {
			return
		}
	}
}

func (s *InMemoryReplayStore) Reset() error {
	s.mu.Lock()
	s.entries = make(map[string]int64)
	s.nextSweep = time.Time{}
	s.mu.Unlock()
	return nil
}

func (s *InMemoryReplayStore) Size() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}
