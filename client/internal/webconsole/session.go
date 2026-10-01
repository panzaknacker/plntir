package webconsole

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

const maxSessions = 128

type Session struct {
	Username     string
	CSRF         string
	UserAgentSum [32]byte
	CreatedAt    time.Time
	ExpiresAt    time.Time
	PrivateUntil time.Time
}

type SessionStore struct {
	mu       sync.Mutex
	sessions map[[32]byte]Session
	duration time.Duration
}

func NewSessionStore(duration time.Duration) *SessionStore {
	return &SessionStore{
		sessions: make(map[[32]byte]Session),
		duration: duration,
	}
}

func (store *SessionStore) Create(username, userAgent string, now time.Time) (string, Session, error) {
	token, err := randomToken(32)
	if err != nil {
		return "", Session{}, err
	}
	csrf, err := randomToken(32)
	if err != nil {
		return "", Session{}, err
	}
	session := Session{
		Username:     username,
		CSRF:         csrf,
		UserAgentSum: sha256.Sum256([]byte(userAgent)),
		CreatedAt:    now,
		ExpiresAt:    now.Add(store.duration),
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	store.pruneLocked(now)
	if len(store.sessions) >= maxSessions {
		return "", Session{}, errors.New("too many active dashboard sessions")
	}
	store.sessions[tokenKey(token)] = session
	return token, session, nil
}

func (store *SessionStore) Get(token, userAgent string, now time.Time) (Session, bool) {
	if token == "" {
		return Session{}, false
	}
	key := tokenKey(token)
	store.mu.Lock()
	defer store.mu.Unlock()
	session, ok := store.sessions[key]
	if !ok {
		return Session{}, false
	}
	if !now.Before(session.ExpiresAt) || session.UserAgentSum != sha256.Sum256([]byte(userAgent)) {
		delete(store.sessions, key)
		return Session{}, false
	}
	return session, true
}

func (store *SessionStore) UnlockPrivate(token, userAgent string, now time.Time, duration time.Duration) (Session, bool) {
	key := tokenKey(token)
	store.mu.Lock()
	defer store.mu.Unlock()
	session, ok := store.sessions[key]
	if !ok || !now.Before(session.ExpiresAt) || session.UserAgentSum != sha256.Sum256([]byte(userAgent)) {
		delete(store.sessions, key)
		return Session{}, false
	}
	session.PrivateUntil = now.Add(duration)
	if session.PrivateUntil.After(session.ExpiresAt) {
		session.PrivateUntil = session.ExpiresAt
	}
	store.sessions[key] = session
	return session, true
}

func (store *SessionStore) LockPrivate(token string) {
	key := tokenKey(token)
	store.mu.Lock()
	defer store.mu.Unlock()
	session, ok := store.sessions[key]
	if !ok {
		return
	}
	session.PrivateUntil = time.Time{}
	store.sessions[key] = session
}

func (store *SessionStore) Delete(token string) {
	store.mu.Lock()
	defer store.mu.Unlock()
	delete(store.sessions, tokenKey(token))
}

func (store *SessionStore) pruneLocked(now time.Time) {
	for key, session := range store.sessions {
		if !now.Before(session.ExpiresAt) {
			delete(store.sessions, key)
		}
	}
}

func (session Session) PrivateActive(now time.Time) bool {
	return !session.PrivateUntil.IsZero() && now.Before(session.PrivateUntil)
}

func randomToken(bytes int) (string, error) {
	value := make([]byte, bytes)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func tokenKey(token string) [32]byte {
	return sha256.Sum256([]byte(token))
}
