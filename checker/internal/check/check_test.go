package check

import (
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// fakeShop emulates the observable behaviour of VulnShop in either mode, so the checker logic
// is tested without PHP. The end-to-end script tests it against the real application.
func fakeShop(secure bool) *httptest.Server {
	var mu sync.Mutex
	reviews := []string{}
	email := "alice@vulnshop.test"
	user := func(r *http.Request) string {
		if c, err := r.Cookie("sid"); err == nil {
			return c.Value
		}
		return ""
	}
	esc := func(s string) string {
		if secure {
			return html.EscapeString(s)
		}
		return s
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/login.php", func(w http.ResponseWriter, r *http.Request) {
		if r.FormValue("username") == "alice" && r.FormValue("password") == "alice123" {
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: "alice"})
			w.WriteHeader(302)
			return
		}
		w.WriteHeader(200)
	})
	mux.HandleFunc("/search.php", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		if !secure && strings.Contains(q, "UNION") {
			fmt.Fprint(w, "<p>0123456789abcdef0123456789abcdef</p>")
			return
		}
		fmt.Fprintf(w, "<h1>Results for %q</h1>", "") // static part
		fmt.Fprint(w, esc(q))
	})
	mux.HandleFunc("/product.php", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Method == "POST" {
			if secure && r.FormValue("csrf") != "tok123" {
				w.WriteHeader(403)
				return
			}
			reviews = append(reviews, r.FormValue("body"))
			w.WriteHeader(302)
			return
		}
		if secure {
			fmt.Fprint(w, `<input type="hidden" name="csrf" value="tok123">`)
		}
		for _, v := range reviews {
			fmt.Fprint(w, "<p>"+esc(v)+"</p>")
		}
	})
	mux.HandleFunc("/order.php", func(w http.ResponseWriter, r *http.Request) {
		owners := map[string]string{"1": "alice", "2": "alice", "3": "admin", "4": "bob"}
		o, ok := owners[r.URL.Query().Get("id")]
		if !ok || (secure && o != user(r)) {
			w.WriteHeader(404)
			return
		}
		fmt.Fprintf(w, "<p>Customer: %s</p>", o)
	})
	mux.HandleFunc("/profile.php", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Method == "POST" {
			if secure && r.FormValue("csrf") != "tok123" {
				w.WriteHeader(403)
				return
			}
			email = r.FormValue("email")
			fmt.Fprint(w, "Email updated.")
			return
		}
		fmt.Fprintf(w, `<input name="email" value="%s">`, email)
	})
	mux.HandleFunc("/download.php", func(w http.ResponseWriter, r *http.Request) {
		f := r.URL.Query().Get("file")
		if secure || !strings.Contains(f, "canary") {
			w.WriteHeader(400)
			return
		}
		fmt.Fprint(w, "VULNSHOP-CANARY")
	})
	mux.HandleFunc("/redirect.php", func(w http.ResponseWriter, r *http.Request) {
		to := r.URL.Query().Get("url")
		if secure && !(strings.HasPrefix(to, "/") && !strings.HasPrefix(to, "//")) {
			to = "/"
		}
		w.Header().Set("Location", to)
		w.WriteHeader(302)
	})
	mux.HandleFunc("/debug.php", func(w http.ResponseWriter, r *http.Request) {
		if secure {
			w.WriteHeader(404)
			return
		}
		fmt.Fprint(w, "VULNSHOP DEBUG")
	})
	mux.HandleFunc("/backup/shop.sqlite.bak", func(w http.ResponseWriter, r *http.Request) {
		if secure {
			w.WriteHeader(404)
			return
		}
		fmt.Fprint(w, "SQLite format 3\x00...")
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if secure {
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("Content-Security-Policy", "default-src 'self'")
		}
		fmt.Fprint(w, "home")
	})
	return httptest.NewServer(mux)
}

func runAgainst(t *testing.T, secure bool) []Result {
	t.Helper()
	srv := fakeShop(secure)
	t.Cleanup(srv.Close)
	c, err := NewClient(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return Run(c, Creds{"alice", "alice123"})
}

func TestAllEightDetectedOnVulnerableTarget(t *testing.T) {
	rs := runAgainst(t, false)
	if len(rs) != 8 {
		t.Fatalf("want 8 results, got %d", len(rs))
	}
	for _, r := range rs {
		if r.Error != "" || !r.Vulnerable || r.Evidence == "" {
			t.Errorf("check %d (%s) should find a flaw: %+v", r.ID, r.Name, r)
		}
	}
}

func TestNoFalsePositivesOnSecureTarget(t *testing.T) {
	for _, r := range runAgainst(t, true) {
		if r.Error != "" || r.Vulnerable {
			t.Errorf("check %d (%s) false positive or error: %+v", r.ID, r.Name, r)
		}
	}
}

func TestCSRFProbeRestoresTheVictimEmail(t *testing.T) {
	srv := fakeShop(false)
	defer srv.Close()
	c, _ := NewClient(srv.URL)
	_ = Run(c, Creds{"alice", "alice123"})
	c2, _ := NewClient(srv.URL)
	if err := c2.Login("alice", "alice123"); err != nil {
		t.Fatal(err)
	}
	r, _ := c2.Get("/profile.php")
	if !strings.Contains(r.Body, "alice@vulnshop.test") {
		t.Fatalf("the checker must leave no side effect on the account: %s", r.Body)
	}
}

func TestUnreachableTargetIsAnErrorNotASecureVerdict(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()
	c, _ := NewClient(url)
	for _, r := range Run(c, Creds{"alice", "alice123"}) {
		if r.Error == "" || r.Vulnerable {
			t.Errorf("check %d must report an error when the target is down: %+v", r.ID, r)
		}
	}
}

func TestBadCredentialsAreReportedAsErrors(t *testing.T) {
	srv := fakeShop(false)
	defer srv.Close()
	c, _ := NewClient(srv.URL)
	errs := 0
	for _, r := range Run(c, Creds{"alice", "wrong"}) {
		if r.Error != "" {
			errs++
		}
	}
	if errs != 4 {
		t.Fatalf("the four authenticated checks must fail loudly, got %d errors", errs)
	}
}

func TestMarkersAreUniqueAndSafe(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 500; i++ {
		m := Marker()
		if seen[m] || !strings.HasPrefix(m, "VC") || strings.ContainsAny(m, "<>\"' ") {
			t.Fatalf("bad marker %q", m)
		}
		seen[m] = true
	}
}

func TestNewClientValidation(t *testing.T) {
	for _, bad := range []string{"", "127.0.0.1:80", "ftp://x", "http://", "::::"} {
		if _, err := NewClient(bad); err == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
	if _, err := NewClient("http://127.0.0.1:8200/"); err != nil {
		t.Fatal(err)
	}
}

func TestIsLoopback(t *testing.T) {
	want := map[string]bool{
		"http://127.0.0.1:8200": true, "http://localhost:80": true, "http://[::1]:80": true, "http://127.5.5.5": true,
		"http://example.com": false, "http://192.168.1.10": false, "http://10.0.0.1:8200": false,
		"http://127.0.0.1.evil.com": false, "http://localhost.evil.com": false, "not a url": false, "": false,
	}
	for in, w := range want {
		if got := IsLoopback(in); got != w {
			t.Errorf("%q: got %v want %v", in, got, w)
		}
	}
}

func TestResponseBodyIsCapped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, strings.Repeat("A", 3<<20))
	}))
	defer srv.Close()
	c, _ := NewClient(srv.URL)
	r, err := c.Get("/")
	if err != nil || len(r.Body) != maxBody {
		t.Fatalf("len=%d err=%v", len(r.Body), err)
	}
}

func TestClientDoesNotFollowRedirects(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://evil.example/", 302)
	}))
	defer srv.Close()
	c, _ := NewClient(srv.URL)
	r, _ := c.Get("/")
	if r.Status != 302 || url.QueryEscape(r.Header.Get("Location")) == "" {
		t.Fatalf("%+v", r)
	}
}
