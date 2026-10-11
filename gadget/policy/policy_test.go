// SPDX-License-Identifier: Apache-2.0
package policy

import (
	"fmt"
	"strings"
	"testing"
)

const digest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func validPolicy(extra string) []byte {
	return []byte(fmt.Sprintf(`{"apiVersion":"agentpolicy.gadget/v1alpha1","kind":"AgentPolicy","metadata":{"name":"test","digest":"%s"},"spec":{"subject":{"taskUID":"task","sessionID":"session"},"failureMode":"closed"%s}}`, digest, extra))
}
func TestParseValid(t *testing.T) {
	p, err := Parse(validPolicy(`,"denyExecutables":[{"id":1,"path":"/usr/bin/curl"}],"denyWrites":[{"id":2,"path":"/tmp/secret"}]`))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Exec) != 1 || len(p.Writes) != 1 || len(p.Networks) != 0 {
		t.Fatalf("unexpected compilation: %#v", p)
	}
}
func TestRejects(t *testing.T) {
	cases := map[string][]byte{
		"empty": {}, "unknown": validPolicy(`,"surprise":true`), "duplicate": []byte(fmt.Sprintf(`{"apiVersion":"agentpolicy.gadget/v1alpha1","apiVersion":"x","kind":"AgentPolicy","metadata":{"name":"x","digest":"%s"},"spec":{"subject":{},"failureMode":"closed"}}`, digest)),
		"trailing": append(validPolicy(""), []byte(` {}`)...), "relative": validPolicy(`,"denyWrites":[{"id":1,"path":"relative"}]`),
		"clean": validPolicy(`,"denyWrites":[{"id":1,"path":"/a/../b"}]`), "network": validPolicy(`,"denyNetworks":[{"id":1,"address":"127.0.0.1","port":80}]`),
		"dupeID": validPolicy(`,"denyExecutables":[{"id":1,"path":"/bin/sh"}],"denyWrites":[{"id":1,"path":"/tmp/x"}]`),
	}
	for n, b := range cases {
		t.Run(n, func(t *testing.T) {
			if _, e := Parse(b); e == nil {
				t.Fatal("accepted invalid policy")
			}
		})
	}
}
func TestBounds(t *testing.T) {
	var rules []string
	for i := 1; i <= MaxExec; i++ {
		rules = append(rules, fmt.Sprintf(`{"id":%d,"path":"/bin/x%d"}`, i, i))
	}
	if _, e := Parse(validPolicy(`,"denyExecutables":[` + strings.Join(rules, ",") + `]`)); e != nil {
		t.Fatalf("max rejected: %v", e)
	}
	rules = append(rules, fmt.Sprintf(`{"id":%d,"path":"/bin/overflow"}`, MaxExec+1))
	if _, e := Parse(validPolicy(`,"denyExecutables":[` + strings.Join(rules, ",") + `]`)); e == nil {
		t.Fatal("max+1 accepted")
	}
}
func TestOversize(t *testing.T) {
	if _, e := Parse(make([]byte, MaxDocument+1)); e == nil {
		t.Fatal("oversize accepted")
	}
}

func TestAllBoundsAndIdentity(t *testing.T) {
	mkPaths := func(n int, start int) string {
		var x []string
		for i := 0; i < n; i++ {
			x = append(x, fmt.Sprintf(`{"id":%d,"path":"/tmp/p%d"}`, start+i, i))
		}
		return strings.Join(x, ",")
	}
	if _, e := Parse(validPolicy(`,"denyWrites":[` + mkPaths(MaxWrites, 1) + `]`)); e != nil {
		t.Fatalf("max writes: %v", e)
	}
	if _, e := Parse(validPolicy(`,"denyWrites":[` + mkPaths(MaxWrites+1, 1) + `]`)); e == nil {
		t.Fatal("max writes + 1 accepted")
	}
	tooLong := strings.Repeat("x", MaxSubject+1)
	if _, e := Parse(validPolicy(`,"subject":{"taskUID":"` + tooLong + `","sessionID":"s"}`)); e == nil {
		t.Fatal("oversize subject accepted")
	}
}

func TestMalformedAndDigestCases(t *testing.T) {
	cases := [][]byte{
		[]byte(`{"apiVersion":"agentpolicy.gadget/v1alpha1"`),
		[]byte("{\xff}"),
		validPolicy(`,"denyWrites":[{"id":1,"path":"/tmp/x"},{"id":2,"path":"/tmp/x"}]`),
		validPolicy(`,"denyNetworks":[{"id":1,"address":"127.0.0.1","port":80},{"id":2,"address":"127.0.0.1","port":80}]`),
	}
	for i, b := range cases {
		if _, e := Parse(b); e == nil {
			t.Fatalf("case %d accepted", i)
		}
	}
	bad := strings.Replace(string(validPolicy("")), digest, "sha256:"+strings.Repeat("A", 64), 1)
	if _, e := Parse([]byte(bad)); e == nil {
		t.Fatal("uppercase digest accepted")
	}
}
