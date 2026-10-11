// SPDX-License-Identifier: Apache-2.0
package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"
)

const (
	MaxDocument = 256 * 1024
	MaxExec     = 64
	MaxWrites   = 128
	MaxPath     = 255
	MaxSubject  = 127
)

type Policy struct {
	APIVersion string   `json:"apiVersion"`
	Kind       string   `json:"kind"`
	Metadata   Metadata `json:"metadata"`
	Spec       Spec     `json:"spec"`
}
type Metadata struct {
	Name   string `json:"name"`
	Digest string `json:"digest"`
}
type Spec struct {
	Subject         Subject       `json:"subject"`
	FailureMode     string        `json:"failureMode"`
	DenyExecutables []PathRule    `json:"denyExecutables,omitempty"`
	DenyWrites      []PathRule    `json:"denyWrites,omitempty"`
	DenyNetworks    []NetworkRule `json:"denyNetworks,omitempty"`
}
type Subject struct {
	TaskUID   string `json:"taskUID"`
	SessionID string `json:"sessionID"`
}
type PathRule struct {
	ID   uint32 `json:"id"`
	Path string `json:"path"`
}
type NetworkRule struct {
	ID         uint32 `json:"id"`
	Address    string `json:"address"`
	Port       uint16 `json:"port"`
	Quarantine bool   `json:"quarantine,omitempty"`
}

type Compiled struct {
	Policy   Policy
	Exec     []PathRule
	Writes   []PathRule
	Networks []CompiledNetwork
}
type CompiledNetwork struct {
	ID         uint32
	Address    [4]byte
	Port       uint16
	Quarantine bool
}

func Parse(raw []byte) (*Compiled, error) {
	if len(raw) == 0 {
		return nil, errors.New("empty policy")
	}
	if len(raw) > MaxDocument {
		return nil, fmt.Errorf("policy exceeds %d bytes", MaxDocument)
	}
	if !json.Valid(raw) {
		return nil, errors.New("malformed JSON or invalid UTF-8")
	}
	if err := rejectDuplicateKeys(raw); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var p Policy
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	if err := ensureEOF(dec); err != nil {
		return nil, err
	}
	if p.APIVersion != "agentpolicy.gadget/v1alpha1" {
		return nil, fmt.Errorf("unsupported apiVersion %q", p.APIVersion)
	}
	if p.Kind != "AgentPolicy" {
		return nil, fmt.Errorf("kind must be AgentPolicy")
	}
	if p.Metadata.Name == "" || len(p.Metadata.Name) > 63 {
		return nil, errors.New("metadata.name length must be 1..63")
	}
	if p.Metadata.Digest == "" || !strings.HasPrefix(p.Metadata.Digest, "sha256:") || len(p.Metadata.Digest) != 71 {
		return nil, errors.New("metadata.digest must be sha256:<64 lowercase hex>")
	}
	for _, c := range p.Metadata.Digest[7:] {
		if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') {
			return nil, errors.New("metadata.digest is not lowercase hex")
		}
	}
	if p.Spec.FailureMode != "closed" && p.Spec.FailureMode != "open" {
		return nil, errors.New("failureMode must be open or closed")
	}
	if len(p.Spec.Subject.TaskUID) > MaxSubject || len(p.Spec.Subject.SessionID) > MaxSubject {
		return nil, errors.New("subject label exceeds 127 bytes")
	}
	if len(p.Spec.DenyExecutables) > MaxExec || len(p.Spec.DenyWrites) > MaxWrites {
		return nil, errors.New("rule count exceeds bounded map capacity")
	}
	if len(p.Spec.DenyNetworks) != 0 {
		return nil, errors.New("network enforcement is unsupported")
	}
	ids := map[uint32]bool{}
	paths := map[string]bool{}
	validatePaths := func(kind string, rules []PathRule) error {
		for _, r := range rules {
			if r.ID == 0 || ids[r.ID] {
				return fmt.Errorf("%s: rule id must be nonzero and globally unique", kind)
			}
			ids[r.ID] = true
			if len(r.Path) == 0 || len(r.Path) > MaxPath || r.Path[0] != '/' || strings.IndexByte(r.Path, 0) >= 0 || filepath.Clean(r.Path) != r.Path {
				return fmt.Errorf("%s rule %d: path must be absolute canonical and <=255 bytes", kind, r.ID)
			}
			if paths[kind+"\x00"+r.Path] {
				return fmt.Errorf("%s: duplicate path %q", kind, r.Path)
			}
			paths[kind+"\x00"+r.Path] = true
		}
		return nil
	}
	if err := validatePaths("exec", p.Spec.DenyExecutables); err != nil {
		return nil, err
	}
	if err := validatePaths("write", p.Spec.DenyWrites); err != nil {
		return nil, err
	}
	out := &Compiled{Policy: p, Exec: append([]PathRule(nil), p.Spec.DenyExecutables...), Writes: append([]PathRule(nil), p.Spec.DenyWrites...)}
	sort.Slice(out.Exec, func(i, j int) bool { return out.Exec[i].ID < out.Exec[j].ID })
	sort.Slice(out.Writes, func(i, j int) bool { return out.Writes[i].ID < out.Writes[j].ID })
	return out, nil
}
func ensureEOF(d *json.Decoder) error {
	var x any
	if err := d.Decode(&x); err != io.EOF {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return fmt.Errorf("trailing data: %w", err)
	}
	return nil
}
func rejectDuplicateKeys(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	var walk func() error
	walk = func() error {
		t, e := d.Token()
		if e != nil {
			return e
		}
		delim, ok := t.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				kt, e := d.Token()
				if e != nil {
					return e
				}
				k := kt.(string)
				if seen[k] {
					return fmt.Errorf("duplicate JSON key %q", k)
				}
				seen[k] = true
				if e = walk(); e != nil {
					return e
				}
			}
			_, e = d.Token()
			return e
		case '[':
			for d.More() {
				if e := walk(); e != nil {
					return e
				}
			}
			_, e = d.Token()
			return e
		}
		return nil
	}
	return walk()
}
