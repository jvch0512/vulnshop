// Package check runs black-box checks for the eight VulnShop flaw classes. Each check sends a
// harmless, uniquely marked probe and decides from the response, the way a scanner would.
package check

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"
)

const maxBody = 1 << 20

// Client is an HTTP client with a cookie jar that does not follow redirects, so Location
// headers can be inspected.
type Client struct {
	Base *url.URL
	http *http.Client
}

func NewClient(base string) (*Client, error) {
	u, err := url.Parse(base)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("invalid target %q: want http(s)://host:port", base)
	}
	jar, _ := cookiejar.New(nil)
	return &Client{
		Base: u,
		http: &http.Client{
			Jar:           jar,
			Timeout:       8 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

// Fresh returns a client with an empty cookie jar for the same target.
func (c *Client) Fresh() *Client {
	n, _ := NewClient(c.Base.String())
	return n
}

type Response struct {
	Status int
	Header http.Header
	Body   string
}

func (c *Client) do(method, path string, form url.Values, hdr map[string]string) (*Response, error) {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequest(method, strings.TrimRight(c.Base.String(), "/")+path, body)
	if err != nil {
		return nil, err
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, err
	}
	return &Response{Status: resp.StatusCode, Header: resp.Header, Body: string(b)}, nil
}

func (c *Client) Get(path string) (*Response, error) { return c.do("GET", path, nil, nil) }

func (c *Client) Post(path string, form url.Values, hdr map[string]string) (*Response, error) {
	return c.do("POST", path, form, hdr)
}

// Login signs in and reports whether the server answered with a redirect (success).
func (c *Client) Login(user, pass string) error {
	r, err := c.Post("/login.php", url.Values{"username": {user}, "password": {pass}}, nil)
	if err != nil {
		return err
	}
	if r.Status != 302 {
		return fmt.Errorf("login as %s failed (HTTP %d)", user, r.Status)
	}
	return nil
}

// Marker returns a unique token so a probe can never match content that was already on the page.
func Marker() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return "VC" + strings.ToUpper(hex.EncodeToString(b))
}
