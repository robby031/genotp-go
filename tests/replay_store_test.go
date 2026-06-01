package genotp_test

import (
	"testing"
	"time"

	genotp "github.com/robby031/genotp-go"
)

func TestInMemoryReplayStoreNoAmnesia(t *testing.T) {
	store := genotp.NewInMemoryReplayStore(3)
	ttl := 1 * time.Minute

	for _, k := range []string{"AAA", "BBB", "CCC"} {
		ok, err := store.CheckAndRecord([]byte(k), ttl)
		if err != nil || !ok {
			t.Fatalf("%s: ok=%v err=%v", k, ok, err)
		}
	}

	ok, err := store.CheckAndRecord([]byte("DDD"), ttl)
	if err != nil || !ok {
		t.Fatalf("DDD: ok=%v err=%v", ok, err)
	}

	for _, k := range []string{"BBB", "CCC", "DDD"} {
		ok, _ := store.CheckAndRecord([]byte(k), ttl)
		if ok {
			t.Errorf("amnesia: %s should still be replay-rejected, got firstSeen=true", k)
		}
	}

	ok, _ = store.CheckAndRecord([]byte("AAA"), ttl)
	if !ok {
		t.Errorf("AAA was evicted, should be firstSeen=true on re-submit")
	}
}

func TestInMemoryReplayStoreTTLExpiry(t *testing.T) {
	store := genotp.NewInMemoryReplayStore(100)
	ttl := 50 * time.Millisecond

	ok, _ := store.CheckAndRecord([]byte("XYZ"), ttl)
	if !ok {
		t.Fatal("first record should succeed")
	}
	ok, _ = store.CheckAndRecord([]byte("XYZ"), ttl)
	if ok {
		t.Fatal("immediate re-record should be replay")
	}

	time.Sleep(80 * time.Millisecond)

	ok, _ = store.CheckAndRecord([]byte("XYZ"), ttl)
	if !ok {
		t.Errorf("after TTL expiry, key should be accepted again")
	}
}

func TestVerifierWithCustomStore(t *testing.T) {
	store := genotp.NewInMemoryReplayStore(10)
	v := genotp.NewVerifierWithStore(5, store, 1*time.Minute)

	if !v.VerifyWithReplayProtection("123456", "123456") {
		t.Fatal("first verify should succeed")
	}
	if v.VerifyWithReplayProtection("123456", "123456") {
		t.Fatal("replay should fail")
	}
	if got := store.Size(); got != 1 {
		t.Errorf("store should have 1 entry, got %d", got)
	}
}

func TestVerifierWrongCodeDoesNotPolluteStore(t *testing.T) {
	store := genotp.NewInMemoryReplayStore(100)
	v := genotp.NewVerifierWithStore(1_000_000, store, 1*time.Minute)

	for i := 0; i < 50; i++ {
		v.VerifyWithReplayProtection("000000", "999999") // selalu salah
	}
	if got := store.Size(); got != 0 {
		t.Errorf("wrong codes leaked into store: size=%d (expected 0)", got)
	}
}
