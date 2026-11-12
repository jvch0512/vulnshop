package main

import (
	"strings"
	"testing"

	"github.com/jvch0512/vulnshop/checker/internal/check"
)

func TestExitCodeSemantics(t *testing.T) {
	ok := check.Result{ID: 1}
	bad := check.Result{ID: 2, Vulnerable: true}
	broken := check.Result{ID: 3, Error: "boom"}
	cases := []struct {
		in   []check.Result
		want int
	}{{[]check.Result{ok}, 0}, {[]check.Result{ok, bad}, 1}, {[]check.Result{bad, broken}, 2}, {nil, 0}}
	for i, c := range cases {
		if got := ExitCode(c.in); got != c.want {
			t.Errorf("case %d: got %d want %d", i, got, c.want)
		}
	}
}

func TestRenderSummaryAndColors(t *testing.T) {
	rs := []check.Result{{ID: 1, Name: "a", OWASP: "A03", Vulnerable: true, Evidence: "found"}, {ID: 2, Name: "b", OWASP: "A01", Evidence: "clean"}, {ID: 3, Name: "c", Error: "down"}}
	plain := render(rs, false)
	if strings.Contains(plain, "\033[") || !strings.Contains(plain, "1 of 3 checks vulnerable") || !strings.Contains(plain, "[VULN]") || !strings.Contains(plain, "[ERR ]") || !strings.Contains(plain, "down") {
		t.Fatalf("%s", plain)
	}
	if !strings.Contains(render(rs, true), "\033[31m") {
		t.Fatal("color output expected")
	}
}
