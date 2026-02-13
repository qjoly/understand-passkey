package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// ---------------------------------------------------------------------------
// In-memory user model
// ---------------------------------------------------------------------------

type User struct {
	ID          []byte
	Surname     string
	Credentials []webauthn.Credential
}

// Satisfy the webauthn.User interface
func (u *User) WebAuthnID() []byte                         { return u.ID }
func (u *User) WebAuthnName() string                       { return u.Surname }
func (u *User) WebAuthnDisplayName() string                { return u.Surname }
func (u *User) WebAuthnCredentials() []webauthn.Credential { return u.Credentials }

// ---------------------------------------------------------------------------
// In-memory store
// ---------------------------------------------------------------------------

type Store struct {
	mu       sync.RWMutex
	users    map[string]*User                 // surname -> User
	sessions map[string]*webauthn.SessionData // session token -> session data
}

func NewStore() *Store {
	return &Store{
		users:    make(map[string]*User),
		sessions: make(map[string]*webauthn.SessionData),
	}
}

func (s *Store) GetUser(surname string) (*User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[surname]
	return u, ok
}

func (s *Store) PutUser(u *User) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[u.Surname] = u
}

func (s *Store) SaveSession(token string, data *webauthn.SessionData) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[token] = data
}

func (s *Store) GetSession(token string) (*webauthn.SessionData, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.sessions[token]
	if ok {
		delete(s.sessions, token) // one-time use
	}
	return d, ok
}

func (s *Store) ListUsers() []*User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*User, 0, len(s.users))
	for _, u := range s.users {
		out = append(out, u)
	}
	return out
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func randomToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

type Server struct {
	webAuthn *webauthn.WebAuthn
	store    *Store
}

func NewServer(rpID string, origins []string) (*Server, error) {
	wconfig := &webauthn.Config{
		RPDisplayName: "Understand Passkeys with a Cup of Coffee",
		RPID:          rpID,
		RPOrigins:     origins,
	}
	w, err := webauthn.New(wconfig)
	if err != nil {
		return nil, fmt.Errorf("webauthn.New: %w", err)
	}
	return &Server{webAuthn: w, store: NewStore()}, nil
}

// POST /api/register/begin  { "surname": "..." }
func (s *Server) handleRegisterBegin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Surname string `json:"surname"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Surname == "" {
		writeErr(w, http.StatusBadRequest, "surname is required")
		return
	}

	user, exists := s.store.GetUser(body.Surname)
	if !exists {
		id := make([]byte, 32)
		rand.Read(id)
		user = &User{ID: id, Surname: body.Surname}
		s.store.PutUser(user)
	}

	// Exclude existing credentials so the authenticator creates a new one
	excludeList := make([]protocol.CredentialDescriptor, len(user.Credentials))
	for i, c := range user.Credentials {
		excludeList[i] = protocol.CredentialDescriptor{
			Type:         protocol.PublicKeyCredentialType,
			CredentialID: c.ID,
		}
	}

	options, session, err := s.webAuthn.BeginRegistration(user,
		webauthn.WithExclusions(excludeList),
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementPreferred),
	)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	token := randomToken()
	s.store.SaveSession(token, session)

	writeJSON(w, http.StatusOK, map[string]any{
		"options": options,
		"token":   token,
	})
}

// POST /api/register/finish  { "token": "...", "surname": "...", "credential": <navigator.credentials.create() response> }
func (s *Server) handleRegisterFinish(w http.ResponseWriter, r *http.Request) {
	// We need to parse the token and surname from the query params, and the
	// body is the raw credential JSON from the browser.
	token := r.URL.Query().Get("token")
	surname := r.URL.Query().Get("surname")

	session, ok := s.store.GetSession(token)
	if !ok {
		writeErr(w, http.StatusBadRequest, "invalid or expired session token")
		return
	}

	user, exists := s.store.GetUser(surname)
	if !exists {
		writeErr(w, http.StatusBadRequest, "unknown user")
		return
	}

	credential, err := s.webAuthn.FinishRegistration(user, *session, r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("registration failed: %v", err))
		return
	}

	user.Credentials = append(user.Credentials, *credential)
	s.store.PutUser(user)

	writeJSON(w, http.StatusOK, map[string]any{
		"status":       "ok",
		"credentialId": base64.RawURLEncoding.EncodeToString(credential.ID),
	})
}

// POST /api/login/begin  { "surname": "..." }
func (s *Server) handleLoginBegin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Surname string `json:"surname"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Surname == "" {
		writeErr(w, http.StatusBadRequest, "surname is required")
		return
	}

	user, exists := s.store.GetUser(body.Surname)
	if !exists {
		writeErr(w, http.StatusNotFound, "user not found – register first")
		return
	}

	options, session, err := s.webAuthn.BeginLogin(user)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	token := randomToken()
	s.store.SaveSession(token, session)

	writeJSON(w, http.StatusOK, map[string]any{
		"options": options,
		"token":   token,
	})
}

// POST /api/login/finish?token=...&surname=...
func (s *Server) handleLoginFinish(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	surname := r.URL.Query().Get("surname")

	session, ok := s.store.GetSession(token)
	if !ok {
		writeErr(w, http.StatusBadRequest, "invalid or expired session token")
		return
	}

	user, exists := s.store.GetUser(surname)
	if !exists {
		writeErr(w, http.StatusBadRequest, "unknown user")
		return
	}

	credential, err := s.webAuthn.FinishLogin(user, *session, r)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, fmt.Sprintf("login failed: %v", err))
		return
	}

	// Update credential sign count
	for i := range user.Credentials {
		if string(user.Credentials[i].ID) == string(credential.ID) {
			user.Credentials[i].Authenticator.SignCount = credential.Authenticator.SignCount
		}
	}
	s.store.PutUser(user)

	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"surname": user.Surname,
	})
}

// GET /api/users
func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	users := s.store.ListUsers()
	type userInfo struct {
		Surname         string `json:"surname"`
		CredentialCount int    `json:"credentialCount"`
	}
	out := make([]userInfo, len(users))
	for i, u := range users {
		out[i] = userInfo{Surname: u.Surname, CredentialCount: len(u.Credentials)}
	}
	writeJSON(w, http.StatusOK, out)
}

func main() {
	port := getEnv("PORT", "8080")
	rpID := getEnv("RP_ID", "localhost")
	rpOrigin := getEnv("RP_ORIGIN", "http://localhost:"+port)

	origins := []string{rpOrigin}

	srv, err := NewServer(rpID, origins)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	mux := http.NewServeMux()

	// API routes
	mux.HandleFunc("POST /api/register/begin", srv.handleRegisterBegin)
	mux.HandleFunc("POST /api/register/finish", srv.handleRegisterFinish)
	mux.HandleFunc("POST /api/login/begin", srv.handleLoginBegin)
	mux.HandleFunc("POST /api/login/finish", srv.handleLoginFinish)
	mux.HandleFunc("GET /api/users", srv.handleListUsers)

	// Serve static files
	mux.Handle("/", http.FileServer(http.Dir("static")))

	log.Printf("Starting server on :%s (rpID=%s, origin=%s)", port, rpID, rpOrigin)
	log.Fatal(http.ListenAndServe(":"+port, mux))
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
