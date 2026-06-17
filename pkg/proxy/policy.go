package proxy

import (
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
)

// For the meanings of the flags, see:
// https://github.com/cilium/cilium/blob/v1.17.16/bpf/lib/common.h#L405
type PolicyEntry struct {
	policymap.PolicyEntryDump
}

func (p PolicyEntry) IsAllow() bool {
	return !p.IsDeny()
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
