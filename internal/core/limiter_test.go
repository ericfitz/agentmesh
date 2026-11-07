package core

import (
	"context"
	"testing"
	"time"
)

type fakeModelEmbedder string

func (f fakeModelEmbedder) Model() string { return string(f) }
func (f fakeModelEmbedder) Embed(context.Context, []string) ([][]float32, error) {
	return nil, nil
}

func TestLimiterCheckThenCharge(t *testing.T) {
	l := NewLimiter(100, 1024, 64)
	now := time.UnixMilli(startMs)
	for i := range 100 {
		if ok, _ := l.Check("pat", 10, now); !ok {
			t.Fatalf("Check %d refused", i)
		}
		l.Charge("pat", 10, now)
	}
	if ok, _ := l.Check("pat", 10, now); ok {
		t.Fatal("101st Check passed")
	}
	// Check alone charges nothing.
	if ok, _ := l.Check("pat", 10, now); ok {
		t.Fatal("Check changed the bucket")
	}
	if ok, _ := l.Check("pat", 10, now.Add(time.Second)); !ok {
		t.Fatal("no message available after 1 s")
	}
}

func TestLimiterBytes(t *testing.T) {
	l := NewLimiter(1000, 64, 1) // 64 KiB/s burst
	now := time.UnixMilli(startMs)
	if ok, _ := l.Check("pat", 64*1024, now); !ok {
		t.Fatal("a full-bucket message refused")
	}
	l.Charge("pat", 64*1024, now)
	if ok, _ := l.Check("pat", 1, now); ok {
		t.Fatal("empty byte bucket passed")
	}
	if ok, _ := l.Check("pat", 1024, now.Add(time.Second)); !ok {
		t.Fatal("bucket did not refill after 1 s")
	}
	if ok, _ := l.Check("pat", 64*1024+1, now.Add(10*time.Second)); ok {
		t.Fatal("a message above the burst cap passed")
	}
}

func TestLimiterChargeGoesNegative(t *testing.T) {
	l := NewLimiter(1, 64, 1)
	now := time.UnixMilli(startMs)
	l.Charge("pat", 1, now)
	l.Charge("pat", 1, now) // two senders passed Check together
	if ok, _ := l.Check("pat", 1, now.Add(time.Second)); ok {
		t.Fatal("a bucket one message in debt passed after 1 s")
	}
	if ok, _ := l.Check("pat", 1, now.Add(2*time.Second)); !ok {
		t.Fatal("bucket did not recover")
	}
}

func TestLimiterKeyedPerIdentity(t *testing.T) { // Decision 86
	l := NewLimiter(1, 64, 1)
	now := time.UnixMilli(startMs)
	l.Charge("pat", 1, now)
	if ok, _ := l.Check("pat", 1, now); ok {
		t.Fatal("pat should be exhausted")
	}
	if ok, _ := l.Check("kim", 1, now); !ok {
		t.Fatal("kim shares pat's bucket")
	}
}

func TestCheckReturnsWait(t *testing.T) {
	l := NewLimiter(2, 64, 1)
	now := time.UnixMilli(startMs)
	if ok, wait := l.Check("pat", 10, now); !ok || wait != 0 {
		t.Fatalf("Check on full buckets = %v, %v; want true, 0", ok, wait)
	}
	l.Charge("pat", 10, now)
	l.Charge("pat", 10, now)
	ok, wait := l.Check("pat", 10, now)
	if ok || wait != 500*time.Millisecond {
		t.Fatalf("Check after two charges = %v, %v; want false, 500ms", ok, wait)
	}
	// Full buckets, a message above the byte cap: the bytes deficit decides.
	l2 := NewLimiter(2, 64, 1)
	ok, wait = l2.Check("kim", 2<<20, now)
	wantBytes := time.Duration((float64(2<<20) - 64*1024) / (64 * 1024) * float64(time.Second))
	if ok || wait != wantBytes || wait <= 500*time.Millisecond {
		t.Fatalf("Check of 2 MiB = %v, %v; want false, %v", ok, wait, wantBytes)
	}
	// Never negative, even in debt.
	for _, n := range []int{0, 1, 1 << 20} {
		if _, w := l.Check("pat", n, now.Add(time.Hour)); w < 0 {
			t.Errorf("negative wait %v", w)
		}
	}
}
