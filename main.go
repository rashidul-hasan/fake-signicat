// Fake Signicat headless BankID API for local development. Not committed (.git/info/exclude).
//
// Run:   go run ./.dev/fake-signicat/main.go
// Auth:  "signicat": {"api_base_url": "http://localhost:8099", "account_id": "x", "api_client_id": "x", "api_client_secret": "x"}
// (auth in docker: "api_base_url": "http://host.docker.internal:8099")
//
// Sign in: start a BankID login as usual, then approve it as a fake user on http://localhost:8099
// (or scan the QR: it's a link to the approve page; set PUBLIC_URL=http://<your LAN IP>:8099 for a phone).
// curl:   curl -XPOST 'localhost:8099/fake/approve?user=anna'   approves the newest pending login
//
// Env: PORT or ADDR (default :8099), PUBLIC_URL (default RENDER_EXTERNAL_URL, else http://localhost:8099),
// AUTO_APPROVE=<user key> approves every new login as that user on its first poll,
// CLIENT_SECRET (optional) required as the client secret on the token endpoint, its token then on every API call,
// UI_PASSWORD (optional) basic auth (any user name) on the approve page and the /fake routes.
//
// Render: Docker web service from this directory (Dockerfile, render.yaml), health check /healthz,
// one instance only (state is in memory). Auth: "api_base_url": "https://<service>.onrender.com",
// "api_client_secret": the CLIENT_SECRET value.
package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

type fakeUser struct {
	Key, FirstName, LastName, Nin string
}

// Edit freely: the same nin always signs in as the same auth user (subject id = hash of the nin).
var presetUsers = []fakeUser{
	{"anna", "Anna", "Andersson", pnr("19900101", "238")},
	{"erik", "Erik", "Johansson", pnr("19850615", "457")},
	{"maria", "Maria", "Karlsson", pnr("19920320", "662")},
	{"lars", "Lars", "Nilsson", pnr("19781111", "891")},
	{"sara", "Sara", "Eriksson", pnr("20000229", "124")},
}

// pnr builds a 12-digit personnummer with a valid Luhn check digit.
func pnr(date, serial string) string {
	s := date[2:] + serial
	sum := 0
	for i, r := range s {
		d := int(r - '0')
		if i%2 == 0 {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
	}
	return date + serial + fmt.Sprint((10-sum%10)%10)
}

type subject struct {
	ID  string `json:"id"`
	Nin struct {
		Value          string `json:"value"`
		IssuingCountry string `json:"issuingCountry"`
	} `json:"nin"`
	Name      string `json:"name"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
}

type session struct {
	ID      string `json:"id"`
	Status  string `json:"status"`
	IdpData struct {
		AutoStartToken string `json:"autoStartToken"`
		QRData         string `json:"qrData"`
		SbidStatus     string `json:"sbidStatus"`
	} `json:"idpData"`
	Subject *subject          `json:"subject,omitempty"`
	Error   map[string]string `json:"error,omitempty"`

	Flow    string    `json:"-"`
	Created time.Time `json:"-"`
}

type server struct {
	mu           sync.Mutex
	sessions     map[string]*session
	publicURL    string
	autoApprove  string
	clientSecret string
	accessToken  string
	uiPassword   string
}

func main() {
	addr := env("ADDR", ":8099")
	if port := os.Getenv("PORT"); port != "" {
		addr = ":" + port
	}
	s := &server{
		sessions:     map[string]*session{},
		publicURL:    strings.TrimRight(env("PUBLIC_URL", env("RENDER_EXTERNAL_URL", "http://localhost:8099")), "/"),
		autoApprove:  os.Getenv("AUTO_APPROVE"),
		clientSecret: os.Getenv("CLIENT_SECRET"),
		accessToken:  "fake-token",
		uiPassword:   os.Getenv("UI_PASSWORD"),
	}
	if s.autoApprove != "" && findUser(s.autoApprove) == nil {
		log.Fatalf("AUTO_APPROVE=%q: no such preset user", s.autoApprove)
	}
	if s.clientSecret != "" {
		// stable across restarts, so auth's cached token survives a redeploy or a free-plan spin-down
		mac := hmac.New(sha256.New, []byte(s.clientSecret))
		mac.Write([]byte("access-token"))
		s.accessToken = hex.EncodeToString(mac.Sum(nil))
	}

	mux := http.NewServeMux()
	// the Signicat API auth calls
	mux.HandleFunc("POST /auth/open/connect/token", s.token)
	mux.Handle("POST /auth/rest/sessions", s.api(s.create))
	mux.Handle("GET /auth/rest/sessions/{id}", s.api(s.get))
	mux.Handle("POST /auth/rest/sessions/{id}/cancel", s.api(s.cancel))
	// the fake "BankID app"
	mux.Handle("GET /{$}", s.ui(s.page))
	mux.Handle("GET /approve/{id}", s.ui(s.page))
	mux.Handle("POST /fake/sessions/{id}/approve", s.ui(s.approve))
	mux.Handle("POST /fake/sessions/{id}/reject", s.ui(s.reject))
	mux.Handle("POST /fake/approve", s.ui(s.approve)) // newest pending session
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })

	log.Printf("fake signicat on %s (approve page %s, client secret %t, ui password %t)",
		addr, s.publicURL, s.clientSecret != "", s.uiPassword != "")
	for _, u := range presetUsers {
		log.Printf("  user %-6s %s %s  %s", u.Key, u.FirstName, u.LastName, u.Nin)
	}
	log.Fatal(http.ListenAndServe(addr, logged(mux)))
}

// token accepts the client secret as basic auth or as a form field (x/oauth2 tries both).
func (s *server) token(w http.ResponseWriter, r *http.Request) {
	if s.clientSecret != "" {
		_, secret, ok := r.BasicAuth()
		if !ok {
			secret = r.PostFormValue("client_secret")
		}
		if !equal(secret, s.clientSecret) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
			return
		}
	}
	writeJSON(w, map[string]any{"access_token": s.accessToken, "token_type": "Bearer", "expires_in": 3600})
}

func (s *server) api(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.clientSecret != "" && !equal(r.Header.Get("Authorization"), "Bearer "+s.accessToken) {
			http.Error(w, `{"title":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		h(w, r)
	})
}

func (s *server) ui(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.uiPassword != "" {
			if _, pw, ok := r.BasicAuth(); !ok || !equal(pw, s.uiPassword) {
				w.Header().Set("WWW-Authenticate", `Basic realm="Fake BankID"`)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		h(w, r)
	})
}

func equal(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }

func (s *server) create(w http.ResponseWriter, r *http.Request) {
	var in struct {
		AdditionalParameters map[string]string `json:"additionalParameters"`
	}
	_ = json.NewDecoder(r.Body).Decode(&in)
	sess := &session{ID: randomID(), Status: "WAITING_FOR_USER", Flow: in.AdditionalParameters["sbid_flow"], Created: time.Now()}
	sess.IdpData.AutoStartToken = randomID()
	sess.IdpData.QRData = s.publicURL + "/approve/" + sess.ID
	sess.IdpData.SbidStatus = "OUTSTANDING_TRANSACTION"
	s.mu.Lock()
	s.sessions[sess.ID] = sess
	s.mu.Unlock()
	log.Printf("session %s created (flow %s)", sess.ID, sess.Flow)
	writeJSON(w, sess)
}

func (s *server) get(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess := s.sessions[r.PathValue("id")]
	if sess == nil {
		http.Error(w, `{"title":"session not found"}`, http.StatusNotFound)
		return
	}
	if sess.Status == "WAITING_FOR_USER" {
		if s.autoApprove != "" {
			complete(sess, *findUser(s.autoApprove))
		} else if time.Since(sess.Created) > 3*time.Minute {
			sess.Status, sess.Error = "ERROR", map[string]string{"code": "expired"}
		}
	}
	writeJSON(w, sess)
}

func (s *server) cancel(w http.ResponseWriter, r *http.Request) {
	s.setStatus(r.PathValue("id"), "CANCELLED")
	w.WriteHeader(http.StatusNoContent)
}

// reject is the user cancelling in the BankID app.
func (s *server) reject(w http.ResponseWriter, r *http.Request) {
	s.setStatus(r.PathValue("id"), "ABORT")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *server) setStatus(id, status string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess := s.sessions[id]; sess != nil && sess.Status == "WAITING_FOR_USER" {
		sess.Status = status
		log.Printf("session %s %s", id, status)
	}
}

// approve takes ?user=<key> (or form field user), or custom first_name, last_name, nin.
func (s *server) approve(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	var u fakeUser
	if key := r.FormValue("user"); key != "" {
		p := findUser(key)
		if p == nil {
			http.Error(w, "unknown user "+key, http.StatusBadRequest)
			return
		}
		u = *p
	} else {
		u = fakeUser{FirstName: strings.TrimSpace(r.FormValue("first_name")), LastName: strings.TrimSpace(r.FormValue("last_name")),
			Nin: strings.TrimSpace(r.FormValue("nin"))}
		if u.FirstName == "" || u.LastName == "" || u.Nin == "" {
			http.Error(w, "user, or first_name + last_name + nin, required", http.StatusBadRequest)
			return
		}
	}

	s.mu.Lock()
	sess := s.sessions[r.PathValue("id")]
	if r.PathValue("id") == "" {
		sess = s.newestPending()
	}
	if sess == nil || sess.Status != "WAITING_FOR_USER" {
		s.mu.Unlock()
		http.Error(w, "no pending session", http.StatusNotFound)
		return
	}
	complete(sess, u)
	s.mu.Unlock()
	log.Printf("session %s approved as %s %s (%s)", sess.ID, u.FirstName, u.LastName, u.Nin)

	if strings.Contains(r.Header.Get("Accept"), "text/html") {
		fmt.Fprintf(w, `<meta name=viewport content="width=device-width"><p style="font:18px system-ui">Signed in as %s %s. <a href="/">Back</a></p>`,
			template.HTMLEscapeString(u.FirstName), template.HTMLEscapeString(u.LastName))
		return
	}
	writeJSON(w, map[string]string{"session": sess.ID, "nin": u.Nin})
}

func complete(sess *session, u fakeUser) {
	sum := sha256.Sum256([]byte("SE:" + u.Nin))
	sub := &subject{ID: "fake-" + hex.EncodeToString(sum[:12]), Name: u.FirstName + " " + u.LastName,
		FirstName: u.FirstName, LastName: u.LastName}
	sub.Nin.Value, sub.Nin.IssuingCountry = u.Nin, "SE"
	sess.Status, sess.Subject = "SUCCESS", sub
	sess.IdpData.SbidStatus = "COMPLETE"
}

func (s *server) newestPending() *session {
	var newest *session
	for _, sess := range s.sessions {
		if sess.Status == "WAITING_FOR_USER" && (newest == nil || sess.Created.After(newest.Created)) {
			newest = sess
		}
	}
	return newest
}

var pageTmpl = template.Must(template.New("page").Parse(`<!doctype html>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Fake BankID</title>
{{if not .One}}<meta http-equiv="refresh" content="2">{{end}}
<style>
 body{font:15px system-ui,sans-serif;max-width:720px;margin:24px auto;padding:0 16px;color:#222}
 .s{border:1px solid #ccc;border-radius:8px;padding:12px;margin:12px 0}
 button{margin:3px;padding:8px 12px;font:inherit;cursor:pointer}
 input{padding:6px;font:inherit;width:140px} code{color:#666} .muted{color:#888}
</style>
<h1>Fake BankID</h1>
{{if .AutoApprove}}<p>AUTO_APPROVE is on: every login signs in as <b>{{.AutoApprove}}</b>.</p>{{end}}
{{range .Pending}}
<div class="s">
 <div>Pending login <code>{{.ID}}</code> <span class="muted">({{.Flow}}, {{.Created.Format "15:04:05"}})</span></div>
 <form method="post" action="/fake/sessions/{{.ID}}/approve">
  {{range $.Users}}<button name="user" value="{{.Key}}">{{.FirstName}} {{.LastName}}</button>{{end}}
 </form>
 <form method="post" action="/fake/sessions/{{.ID}}/approve">
  <input name="first_name" placeholder="First name" required>
  <input name="last_name" placeholder="Last name" required>
  <input name="nin" placeholder="Personnummer (12 digits)" required>
  <button>Sign in as new user</button>
 </form>
 <form method="post" action="/fake/sessions/{{.ID}}/reject"><button>Cancel in BankID</button></form>
</div>
{{else}}<p class="muted">{{if .One}}This login is no longer pending.{{else}}No pending logins. Start a BankID sign-in; it shows up here.{{end}}</p>{{end}}
<h3>Users</h3>
<table>{{range .Users}}<tr><td>{{.Key}}</td><td>{{.FirstName}} {{.LastName}}</td><td><code>{{.Nin}}</code></td></tr>{{end}}</table>
`))

func (s *server) page(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	var pending []session
	for _, sess := range s.sessions {
		if sess.Status == "WAITING_FOR_USER" && (r.PathValue("id") == "" || r.PathValue("id") == sess.ID) {
			pending = append(pending, *sess)
		}
	}
	s.mu.Unlock()
	sort.Slice(pending, func(i, j int) bool { return pending[i].Created.After(pending[j].Created) })
	_ = pageTmpl.Execute(w, map[string]any{"Pending": pending, "Users": presetUsers, "One": r.PathValue("id") != "",
		"AutoApprove": s.autoApprove})
}

func findUser(key string) *fakeUser {
	for i := range presetUsers {
		if presetUsers[i].Key == key {
			return &presetUsers[i]
		}
	}
	return nil
}

func randomID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	h := hex.EncodeToString(b)
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func logged(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && (strings.HasPrefix(r.URL.Path, "/auth/rest/sessions/") || r.URL.Path == "/healthz") {
			h.ServeHTTP(w, r) // polled every second / health checks: too noisy to log
			return
		}
		log.Printf("%s %s", r.Method, r.URL.Path)
		h.ServeHTTP(w, r)
	})
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
