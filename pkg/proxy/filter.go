package proxy

import (
	"context"
	"slices"

	"github.com/cilium/cilium/pkg/identity"

	"github.com/cybozu-go/network-policy-viewer/pkg/cidr"
)

type PolicyFilter func(ctx context.Context, client *Client, p *PolicyEntry) (bool, error)

func MakeBasicFilter(ingress, egress, allowed, denied, used, unused bool) PolicyFilter {
	if ingress && egress && allowed && denied && used && unused {
		// no filter
		return nil
	}
	return func(ctx context.Context, client *Client, p *PolicyEntry) (bool, error) {
		ret := true
		switch {
		case p.IsIngress():
			ret = ret && ingress
		case p.IsEgress():
			ret = ret && egress
		}
		switch {
		case p.IsAllow():
			ret = ret && allowed
		case p.IsDeny():
			ret = ret && denied
		}
		switch {
		case p.Bytes > 0:
			ret = ret && used
		case p.Bytes == 0:
			ret = ret && unused
		}
		return ret, nil
	}
}

func MakeIdentityFilter(ingress, egress bool, id uint32) PolicyFilter {
	return func(ctx context.Context, client *Client, p *PolicyEntry) (bool, error) {
		if (p.IsIngress() && !ingress) || (p.IsEgress() && !egress) {
			return false, nil
		}
		if p.Key.Identity == 0 {
			return true, nil
		}

		// This filter is looking for a global identity
		idObj := identity.NumericIdentity(p.Key.Identity)
		if idObj.HasLocalScope() {
			return false, nil
		}
		return (p.Key.Identity == 0) || (p.Key.Identity == id), nil
	}
}

func MakeCIDRFilter(ingress, egress bool, s cidr.Set) PolicyFilter {
	return func(ctx context.Context, client *Client, p *PolicyEntry) (bool, error) {
		if (p.IsIngress() && !ingress) || (p.IsEgress() && !egress) {
			return false, nil
		}

		idObj := identity.NumericIdentity(p.Key.Identity)
		switch idObj {
		case identity.IdentityUnknown,
			identity.ReservedIdentityWorld,
			identity.ReservedIdentityWorldIPv4,
			identity.ReservedIdentityWorldIPv6:
			return true, nil
		}

		// If the identity is not locally-scoped, it is not representing a CIDR
		if !idObj.HasLocalScope() {
			return false, nil
		}

		// Retrieve identity information
		idCIDR, err := client.GetCIDRForIdentity(ctx, p.Key.Identity)
		if err != nil {
			return false, err
		}

		// Check
		return s.Overlaps(*idCIDR), nil
	}
}

func MakeAllFilter(filters ...PolicyFilter) PolicyFilter {
	// Please make sure to put a basic filter first for faster computation
	arr := make([]PolicyFilter, 0)
	for _, f := range filters {
		if f != nil {
			arr = append(arr, f)
		}
	}
	switch len(arr) {
	case 0:
		return nil
	case 1:
		return arr[0]
	default:
		return func(ctx context.Context, client *Client, p *PolicyEntry) (bool, error) {
			for _, f := range arr {
				result, err := f(ctx, client, p)
				if !result || err != nil {
					return result, err
				}
			}
			return true, nil
		}
	}
}

func FilterPolicyMap(ctx context.Context, client *Client, policies []PolicyEntry, pred PolicyFilter) ([]PolicyEntry, error) {
	if pred == nil {
		return policies, nil
	}

	// If any error is observed, cancel the remaining work and returns the error
	var err error
	policies = slices.DeleteFunc(policies, func(p PolicyEntry) bool {
		if err != nil {
			return false
		}
		var ok bool
		ok, err = pred(ctx, client, &p)
		return !ok
	})
	if err != nil {
		return nil, err
	}
	return policies, nil
}
