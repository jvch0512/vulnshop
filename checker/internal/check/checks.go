package check

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// Result is the outcome of one flaw check.
type Result struct {
	ID         int    `json:"id"`
	Name       string `json:"name"`
	OWASP      string `json:"owasp"`
	Vulnerable bool   `json:"vulnerable"`
	Evidence   string `json:"evidence"`
	Error      string `json:"error,omitempty"`
}

type Creds struct{ User, Pass string }

type check struct {
	id    int
	name  string
	owasp string
	run   func(c *Client, cr Creds) (bool, string, error)
}

var all = []check{
	{1, "SQL injection in search", "A03:2021 Injection", sqli},
	{2, "Reflected XSS in search", "A03:2021 Injection", reflectedXSS},
	{3, "Stored XSS in reviews", "A03:2021 Injection", storedXSS},
	{4, "IDOR on orders", "A01:2021 Broken Access Control", idor},
	{5, "CSRF on profile update", "A01:2021 Broken Access Control", csrf},
	{6, "Path traversal in invoice download", "A01:2021 Broken Access Control", traversal},
	{7, "Open redirect", "A01:2021 Broken Access Control", openRedirect},
	{8, "Security misconfiguration", "A05:2021 Security Misconfiguration", misconfig},
}

// Run executes every check. A check that cannot complete reports an error instead of a verdict,
// so an unreachable target is never mistaken for a secure one.
func Run(c *Client, cr Creds) []Result {
	out := make([]Result, 0, len(all))
	for _, ch := range all {
		vuln, ev, err := ch.run(c.Fresh(), cr)
		r := Result{ID: ch.id, Name: ch.name, OWASP: ch.owasp, Vulnerable: vuln, Evidence: ev}
		if err != nil {
			r.Error = err.Error()
			r.Vulnerable = false
		}
		out = append(out, r)
	}
	return out
}

var hash32 = regexp.MustCompile(`\b[0-9a-f]{32}\b`)

func sqli(c *Client, _ Creds) (bool, string, error) {
	payload := "zzz' UNION SELECT id,username,password,0,0 FROM users-- "
	r, err := c.Get("/search.php?q=" + url.QueryEscape(payload))
	if err != nil {
		return false, "", err
	}
	if h := hash32.FindString(r.Body); h != "" {
		return true, "UNION injection returned a password hash (unsalted MD5): " + h, nil
	}
	if strings.Contains(r.Body, "SQLSTATE") || strings.Contains(r.Body, "syntax error") {
		return true, "injected quote produced a database error page", nil
	}
	return false, "injection payload returned no data", nil
}

func reflectedXSS(c *Client, _ Creds) (bool, string, error) {
	m := Marker()
	payload := "<svg onload=" + m + ">"
	r, err := c.Get("/search.php?q=" + url.QueryEscape(payload))
	if err != nil {
		return false, "", err
	}
	if strings.Contains(r.Body, payload) {
		return true, "payload reflected unescaped: " + payload, nil
	}
	return false, "payload was HTML-escaped", nil
}

var csrfField = regexp.MustCompile(`name="csrf" value="([0-9a-f]+)"`)

func storedXSS(c *Client, cr Creds) (bool, string, error) {
	if err := c.Login(cr.User, cr.Pass); err != nil {
		return false, "", err
	}
	page, err := c.Get("/product.php?id=1")
	if err != nil {
		return false, "", err
	}
	m := Marker()
	payload := "<img src=x onerror=" + m + ">"
	form := url.Values{"body": {payload}}
	if t := csrfField.FindStringSubmatch(page.Body); t != nil {
		form.Set("csrf", t[1]) // behave like a browser: submit the token the form carries
	}
	if _, err := c.Post("/product.php?id=1", form, nil); err != nil {
		return false, "", err
	}
	after, err := c.Get("/product.php?id=1")
	if err != nil {
		return false, "", err
	}
	if strings.Contains(after.Body, payload) {
		return true, "review stored and rendered unescaped: " + payload, nil
	}
	return false, "stored payload was HTML-escaped on output", nil
}

var customer = regexp.MustCompile(`Customer: ([A-Za-z0-9_]+)`)

func idor(c *Client, cr Creds) (bool, string, error) {
	if err := c.Login(cr.User, cr.Pass); err != nil {
		return false, "", err
	}
	var foreign []string
	for id := 1; id <= 8; id++ {
		r, err := c.Get(fmt.Sprintf("/order.php?id=%d", id))
		if err != nil {
			return false, "", err
		}
		if m := customer.FindStringSubmatch(r.Body); m != nil && r.Status == 200 && m[1] != cr.User {
			foreign = append(foreign, fmt.Sprintf("#%d (%s)", id, m[1]))
		}
	}
	if len(foreign) > 0 {
		return true, fmt.Sprintf("%s can read other customers' orders: %s", cr.User, strings.Join(foreign, ", ")), nil
	}
	return false, "orders of other users are not readable", nil
}

var emailField = regexp.MustCompile(`name="email" value="([^"]*)"`)

func csrf(c *Client, cr Creds) (bool, string, error) {
	if err := c.Login(cr.User, cr.Pass); err != nil {
		return false, "", err
	}
	page, err := c.Get("/profile.php")
	if err != nil {
		return false, "", err
	}
	original := ""
	if m := emailField.FindStringSubmatch(page.Body); m != nil {
		original = m[1]
	}
	probe := Marker() + "@csrf.test"
	// A cross-site attacker cannot read the token, so the forged request carries none.
	r, err := c.Post("/profile.php", url.Values{"email": {strings.ToLower(probe)}}, map[string]string{"Origin": "http://evil.example"})
	if err != nil {
		return false, "", err
	}
	vuln := r.Status == 200 && strings.Contains(r.Body, "Email updated")
	if vuln && original != "" {
		_, _ = c.Post("/profile.php", url.Values{"email": {original}}, nil) // put the victim's email back
	}
	if vuln {
		return true, "forged cross-site POST without a token changed the account email", nil
	}
	return false, fmt.Sprintf("forged request rejected (HTTP %d)", r.Status), nil
}

func traversal(c *Client, cr Creds) (bool, string, error) {
	if err := c.Login(cr.User, cr.Pass); err != nil {
		return false, "", err
	}
	for _, p := range []string{"../canary.txt", "..%2fcanary.txt"} {
		r, err := c.Get("/download.php?file=" + p)
		if err != nil {
			return false, "", err
		}
		if r.Status == 200 && strings.Contains(r.Body, "VULNSHOP-CANARY") {
			return true, "file=" + p + " returned a file from outside the invoices directory", nil
		}
	}
	return false, "traversal sequences were rejected", nil
}

func openRedirect(c *Client, _ Creds) (bool, string, error) {
	for _, target := range []string{"https://evil.example/x", "//evil.example/x"} {
		r, err := c.Get("/redirect.php?url=" + url.QueryEscape(target))
		if err != nil {
			return false, "", err
		}
		loc := r.Header.Get("Location")
		if u, err := url.Parse(loc); err == nil && r.Status >= 300 && r.Status < 400 && u.Host == "evil.example" {
			return true, fmt.Sprintf("redirects to an external host: Location: %s", loc), nil
		}
	}
	return false, "only local redirects are allowed", nil
}

func misconfig(c *Client, _ Creds) (bool, string, error) {
	var issues []string
	if r, err := c.Get("/debug.php"); err != nil {
		return false, "", err
	} else if r.Status == 200 && strings.Contains(r.Body, "DEBUG") {
		issues = append(issues, "debug page exposed")
	}
	if r, err := c.Get("/backup/shop.sqlite.bak"); err != nil {
		return false, "", err
	} else if r.Status == 200 && strings.HasPrefix(r.Body, "SQLite format 3") {
		issues = append(issues, "database backup downloadable")
	}
	home, err := c.Get("/")
	if err != nil {
		return false, "", err
	}
	for _, h := range []string{"X-Frame-Options", "X-Content-Type-Options", "Content-Security-Policy"} {
		if home.Header.Get(h) == "" {
			issues = append(issues, "missing "+h)
		}
	}
	if len(issues) > 0 {
		return true, strings.Join(issues, "; "), nil
	}
	return false, "no debug page, no backup, security headers present", nil
}
