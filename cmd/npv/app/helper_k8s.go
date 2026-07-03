package app

import (
	"context"
	"errors"
	"math/rand/v2"
	"strconv"
	"strings"
	"sync"

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	k8sMutex                sync.Mutex
	cachedIdentities        map[uint32]*ciliumv2.CiliumIdentity
	cachedIdentityEndpoints map[uint32][]*ciliumv2.CiliumEndpoint
	cachedIdentityExample   = make(map[uint32]*ciliumv2.CiliumEndpoint)
)

func parseNamespacedName(nn string) (types.NamespacedName, error) {
	li := strings.Split(nn, "/")
	if len(li) != 2 {
		return types.NamespacedName{}, errors.New("input is not NAMESPACE/NAME")
	}
	return types.NamespacedName{Namespace: li[0], Name: li[1]}, nil
}

func getPodIdentity(ctx context.Context, c client.Client, namespace, name string) (uint32, error) {
	var ep ciliumv2.CiliumEndpoint
	if err := c.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, &ep); err != nil {
		return 0, err
	}
	return uint32(ep.Status.Identity.ID), nil
}

// key: identity number
// value: CiliumIdentity resource
func getIdentityResourceMap(ctx context.Context, c client.Client) (map[uint32]*ciliumv2.CiliumIdentity, error) {
	if cachedIdentities != nil {
		return cachedIdentities, nil
	}

	var li ciliumv2.CiliumIdentityList
	if err := c.List(ctx, &li); err != nil {
		return nil, err
	}

	ret := make(map[uint32]*ciliumv2.CiliumIdentity)
	for _, item := range li.Items {
		id, err := strconv.Atoi(item.GetName())
		if err != nil {
			return nil, err
		}
		ret[uint32(id)] = &item
	}
	cachedIdentities = ret
	return ret, nil
}

// key: identity number
// value: CiliumEndpoint array
func getIdentityEndpoints(ctx context.Context, c client.Client) (map[uint32][]*ciliumv2.CiliumEndpoint, error) {
	if cachedIdentityEndpoints != nil {
		return cachedIdentityEndpoints, nil
	}

	var li ciliumv2.CiliumEndpointList
	if err := c.List(ctx, &li); err != nil {
		return nil, err
	}

	ret := make(map[uint32][]*ciliumv2.CiliumEndpoint)
	for _, ep := range li.Items {
		identity := uint32(ep.Status.Identity.ID)
		ret[identity] = append(ret[identity], &ep)
	}
	cachedIdentityEndpoints = ret
	return ret, nil
}

// getIdentityExample returns a consistent example endpoint for a CiliumIdentity within process' lifetime.
// key: identity number
// value: CiliumEndpoint
func getIdentityExample(ctx context.Context, c client.Client, id uint32) (*ciliumv2.CiliumEndpoint, error) {
	k8sMutex.Lock()
	defer k8sMutex.Unlock()

	if cached, ok := cachedIdentityExample[id]; ok {
		return cached, nil
	}

	idEndpoints, err := getIdentityEndpoints(ctx, c)
	if err != nil {
		return nil, err
	}

	eps, ok := idEndpoints[id]
	if !ok || len(eps) == 0 {
		cachedIdentityExample[id] = nil
		return nil, nil
	}

	i := rand.IntN(len(eps))
	ret := eps[i]
	cachedIdentityExample[id] = ret
	return ret, nil
}
