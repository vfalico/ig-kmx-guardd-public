// SPDX-License-Identifier: Apache-2.0
package main

import (
	"fmt"

	api "github.com/inspektor-gadget/inspektor-gadget/wasmapi/go"
	"github.com/vfalico/ig-kmx-guardd-public/gadget/policy"
)

type stateValue struct{ State, Quarantined, Generation, FailureClosed uint32 }
type ruleValue struct{ RuleID, Quarantine uint32 }
type writeRuleValue struct {
	RuleID, Quarantine uint32
	Path               pathKey
}
type pathKey [256]byte
type netKey struct {
	Address [4]byte
	PortBE  uint16
	Pad     uint16
}

const stateActive uint32 = 1

func fail(message string) int32 {
	api.Warnf("agentpolicy initialization failed: %s", message)
	return 1
}
func pathHash(p string) uint64 {
	var h uint64 = 14695981039346656037
	for i := 0; i < len(p); i++ {
		h ^= uint64(p[i])
		h *= 1099511628211
	}
	return h
}

func pathToKey(p string) pathKey { var k pathKey; copy(k[:], p); return k }

//go:wasmexport gadgetStart
func gadgetStart() int32 {
	raw, err := api.GetParamValue("policy", policy.MaxDocument+1)
	if err != nil {
		return fail(fmt.Sprintf("read policy parameter: %v", err))
	}
	compiled, err := policy.Parse([]byte(raw))
	if err != nil {
		return fail(err.Error())
	}
	stateMap, err := api.GetMap("policy_state")
	if err != nil {
		return fail(err.Error())
	}
	execMap, err := api.GetMap("exec_rules")
	if err != nil {
		return fail(err.Error())
	}
	writeMap, err := api.GetMap("write_rules")
	if err != nil {
		return fail(err.Error())
	}
	networkMap, err := api.GetMap("network_rules")
	if err != nil {
		return fail(err.Error())
	}
	// Maps are created fresh per IG invocation. ACTIVE is the one-way commit point.
	for _, r := range compiled.Exec {
		if err := execMap.Put(pathToKey(r.Path), ruleValue{RuleID: r.ID}); err != nil {
			return fail(fmt.Sprintf("exec rule %d: %v", r.ID, err))
		}
	}
	for _, r := range compiled.Writes {
		if err := writeMap.Put(pathHash(r.Path), writeRuleValue{RuleID: r.ID, Path: pathToKey(r.Path)}); err != nil {
			return fail(fmt.Sprintf("write rule %d: %v", r.ID, err))
		}
	}
	for _, r := range compiled.Networks {
		q := uint32(0)
		if r.Quarantine {
			q = 1
		}
		// wasm32 is little-endian; PortBE's in-memory bytes must match sockaddr_in.
		k := netKey{Address: r.Address, PortBE: uint16(r.Port>>8) | uint16(r.Port<<8)}
		if err := networkMap.Put(k, ruleValue{RuleID: r.ID, Quarantine: q}); err != nil {
			return fail(fmt.Sprintf("network rule %d: %v", r.ID, err))
		}
	}
	var key uint32
	var failureClosed uint32
	if compiled.Policy.Spec.FailureMode == "closed" {
		failureClosed = 1
	}
	if err := stateMap.Put(key, stateValue{State: stateActive, Generation: 1, FailureClosed: failureClosed}); err != nil {
		return fail(fmt.Sprintf("commit ACTIVE: %v", err))
	}
	api.Infof("READY policy=%s activationVersion=1 digest=%s exec=%d writes=%d networks=%d failureMode=%s", compiled.Policy.Metadata.Name, compiled.Policy.Metadata.Digest, len(compiled.Exec), len(compiled.Writes), len(compiled.Networks), compiled.Policy.Spec.FailureMode)
	return 0
}
func main() {}
