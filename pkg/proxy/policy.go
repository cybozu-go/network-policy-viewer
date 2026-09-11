package proxy

import (
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
)

// For the meanings of the flags, see:
// https://github.com/cilium/cilium/blob/v1.18.6/bpf/lib/common.h#L330
type PolicyEntry struct {
	policymap.PolicyEntryDump
}

func (p PolicyEntry) IsAllow() bool {
	return !p.IsDeny()
}

// IsStatsAvailable reports whether Packets/Bytes reflect real counters.
// Since Cilium 1.18, policy statistics are tracked in a separate per-CPU LRU
// map, and an entry is only created there once a packet actually matches it;
// until then (or once evicted from the LRU under memory pressure), lookups
// report policymap.StatNotAvailable rather than 0.
//
// Notably, a policy entry is otherwise never proactively zeroed in that map
// (PolicyMap.Update only does so when the agent runs with --debug), so in
// practice a confirmed "0 bytes" is effectively unobservable in production:
// an entry either has real (non-zero) counters, or its stats are unavailable.
func (p PolicyEntry) IsStatsAvailable() bool {
	return p.Packets != policymap.StatNotAvailable && p.Bytes != policymap.StatNotAvailable
}

func (p PolicyEntry) IsIngress() bool {
	return !p.IsEgress()
}

func (p PolicyEntry) IsEgress() bool {
	return p.Key.TrafficDirection == uint8(trafficdirection.Egress)
}

func (p PolicyEntry) GetProtocol() uint8 {
	return p.Key.Nexthdr
}

func (p PolicyEntry) IsWildcardProtocol() bool {
	return p.Key.Nexthdr == 0
}

func (p PolicyEntry) IsWildcardPort() bool {
	return p.Key.GetDestPort() == 0
}
