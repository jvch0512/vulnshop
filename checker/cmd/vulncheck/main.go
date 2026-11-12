package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/jvch0512/vulnshop/checker/internal/check"
)

// ExitCode: 0 clean, 1 at least one vulnerability, 2 the scan could not complete.
func ExitCode(rs []check.Result) int {
	code := 0
	for _, r := range rs {
		if r.Error != "" {
			return 2
		}
		if r.Vulnerable {
			code = 1
		}
	}
	return code
}

func render(rs []check.Result, color bool) string {
	paint := func(s, c string) string {
		if !color {
			return s
		}
		return c + s + "\033[0m"
	}
	var b strings.Builder
	vuln := 0
	for _, r := range rs {
		status := paint("PASS", "\033[32m")
		switch {
		case r.Error != "":
			status = paint("ERR ", "\033[33m")
		case r.Vulnerable:
			status = paint("VULN", "\033[31m")
			vuln++
		}
		ev := r.Evidence
		if r.Error != "" {
			ev = r.Error
		}
		fmt.Fprintf(&b, "%d. [%s] %-36s %s\n     %s\n", r.ID, status, r.Name, r.OWASP, ev)
	}
	fmt.Fprintf(&b, "\n%d of %d checks vulnerable\n", vuln, len(rs))
	return b.String()
}

func main() {
	target := flag.String("target", "http://127.0.0.1:8200", "VulnShop base URL")
	user := flag.String("user", "alice", "low-privilege test account")
	pass := flag.String("pass", "alice123", "password of the test account")
	asJSON := flag.Bool("json", false, "machine-readable output")
	own := flag.Bool("i-own-this", false, "allow a non-loopback target (only for systems you own)")
	flag.Parse()

	if !check.IsLoopback(*target) && !*own {
		fmt.Fprintln(os.Stderr, "refusing to send attack payloads to a non-loopback target; pass -i-own-this only for systems you own")
		os.Exit(2)
	}
	c, err := check.NewClient(*target)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	rs := check.Run(c, check.Creds{User: *user, Pass: *pass})
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rs)
	} else {
		st, _ := os.Stdout.Stat()
		fmt.Print(render(rs, st != nil && st.Mode()&os.ModeCharDevice != 0))
	}
	os.Exit(ExitCode(rs))
}
