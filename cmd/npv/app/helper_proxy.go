package app

import (
	"context"
	"net"
	"slices"
	"sync"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ip"
	corev1 "k8s.io/api/core/v1"

	"github.com/cybozu-go/network-policy-viewer/pkg/cidr"
	"github.com/cybozu-go/network-policy-viewer/pkg/proxy"
)

type policyFilter func(ctx context.Context, client *proxy.Client, p *proxy.PolicyEntry) (bool, error)

func makeBasicFilter(ingress, egress, allowed, denied, used, unused bool) policyFilter {
	if ingress && egress && allowed && denied && used && unused {
		// no filter
		return nil
	}
	return func(ctx context.Context, client *proxy.Client, p *proxy.PolicyEntry) (bool, error) {
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

func makeIdentityFilter(ingress, egress bool, id uint32) policyFilter {
	return func(ctx context.Context, client *proxy.Client, p *proxy.PolicyEntry) (bool, error) {
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

func makeCIDRFilter(ingress, egress bool, incl []*net.IPNet, excl []*net.IPNet) policyFilter {
	incl = ip.RemoveCIDRs(incl, excl)

	return func(ctx context.Context, client *proxy.Client, p *proxy.PolicyEntry) (bool, error) {
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
		for _, c := range incl {
			if cidr.IsChildCIDR(c, idCIDR) || cidr.IsChildCIDR(idCIDR, c) {
				return true, nil
			}
		}
		return false, nil
	}
}

func makeAllFilter(filters ...policyFilter) policyFilter {
	// Please make sure to put a basic filter first for faster computation
	arr := make([]policyFilter, 0)
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
		return func(ctx context.Context, client *proxy.Client, p *proxy.PolicyEntry) (bool, error) {
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

func filterPolicyMap(ctx context.Context, client *proxy.Client, policies []proxy.PolicyEntry, pred policyFilter) ([]proxy.PolicyEntry, error) {
	if pred == nil {
		return policies, nil
	}

	// If any error is observed, cancel the remaining work and returns the error
	var err error
	policies = slices.DeleteFunc(policies, func(p proxy.PolicyEntry) bool {
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

func mapNodeReduce[T any](pods []*corev1.Pod, initFunc func() T, mapFunc func(*corev1.Pod) T, reduceFunc func(T, T) T) T {
	var mu sync.Mutex
	pods = slices.Clone(pods)
	nodes := make(map[string]bool)
	for _, p := range pods {
		nodes[p.Spec.NodeName] = false
	}

	numJobs := min(rootOptions.jobs, len(pods), len(nodes))
	if numJobs == 0 {
		return initFunc()
	}

	pick := func() (*corev1.Pod, bool) {
		mu.Lock()
		defer mu.Unlock()
		for i := len(pods) - 1; i >= 0; i-- {
			p := pods[i]
			if !nodes[p.Spec.NodeName] {
				nodes[p.Spec.NodeName] = true
				pods = slices.Delete(pods, i, i+1)
				return p, true
			}
		}
		return nil, false
	}
	release := func(p *corev1.Pod) {
		mu.Lock()
		defer mu.Unlock()
		if !nodes[p.Spec.NodeName] {
			panic("internal error")
		}
		nodes[p.Spec.NodeName] = false
	}

	var wg sync.WaitGroup
	values := make([]T, numJobs)
	for i := 0; i < numJobs; i++ {
		wg.Go(func() {
			values[i] = initFunc()
			for {
				p, found := pick()
				if !found {
					return
				}
				v := mapFunc(p)
				release(p)

				values[i] = reduceFunc(values[i], v)
			}
		})
	}
	wg.Wait()

	result := values[0]
	for i := 1; i < numJobs; i++ {
		result = reduceFunc(result, values[i])
	}
	return result
}

func compactBy[T any](x []T, cmp func(*T, *T) int, merge func(*T, *T) *T) []T {
	ret := make([]T, 0, len(x))
	if len(x) == 0 {
		return ret
	}

	ret = append(ret, x[0])
	for i := 1; i < len(x); i++ {
		last := &ret[len(ret)-1]
		next := &x[i]

		if cmp(last, next) == 0 {
			ret[len(ret)-1] = *merge(last, next)
		} else {
			ret = append(ret, *next)
		}
	}
	return ret
}

func mergeBy[T any](x, y []T, cmp func(*T, *T) int, merge func(*T, *T) *T) []T {
	var i, j int
	ret := make([]T, 0, len(x)+len(y))

	for i < len(x) && j < len(y) {
		c := cmp(&x[i], &y[j])

		switch {
		case c < 0:
			ret = append(ret, x[i])
			i++

		case c > 0:
			ret = append(ret, y[j])
			j++

		default:
			ret = append(ret, *merge(&x[i], &y[j]))
			i++
			j++
		}
	}

	ret = append(ret, x[i:]...)
	ret = append(ret, y[j:]...)
	return ret
}
