package check

import (
	"net"
	"net/url"
	"strings"
)

// IsLoopback reports whether the target host is the local machine. The checker sends attack
// payloads, so it refuses anything else unless the operator explicitly says they own it.
func IsLoopback(target string) bool {
	u, err := url.Parse(target)
	if err != nil {
		return false
	}
	h := strings.TrimSuffix(u.Hostname(), ".")
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}
