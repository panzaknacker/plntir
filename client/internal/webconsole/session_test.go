package webconsole

import (
	"testing"
	"time"
)

func TestSessionLifecycleAndPrivateExpiry(t *testing.T) {
	now := time.Date(2026, 8, 30, 19, 0, 0, 0, time.UTC)
	store := NewSessionStore(20 * time.Minute)
	token, session, err := store.Create("operator", "test-agent", now)
	if err != nil {
		t.Fatal(err)
	}
	if session.PrivateActive(now) {
		t.Fatal("new session unexpectedly has private access")
	}
	if _, ok := store.Get(token, "wrong-agent", now); ok {
		t.Fatal("session was accepted with another user agent")
	}

	// the previous failed lookup invalidates the token by design.
	token, _, err = store.Create("operator", "test-agent", now)
	if err != nil {
		t.Fatal(err)
	}
	unlocked, ok := store.UnlockPrivate(token, "test-agent", now, 10*time.Minute)
	if !ok || !unlocked.PrivateActive(now.Add(9*time.Minute)) {
		t.Fatal("private session was not activated")
	}
	if unlocked.PrivateActive(now.Add(11 * time.Minute)) {
		t.Fatal("private session did not expire")
	}
	store.LockPrivate(token)
	locked, ok := store.Get(token, "test-agent", now)
	if !ok || locked.PrivateActive(now) {
		t.Fatal("private session did not lock")
	}
	if _, ok := store.Get(token, "test-agent", now.Add(21*time.Minute)); ok {
		t.Fatal("expired main session remained valid")
	}
}
