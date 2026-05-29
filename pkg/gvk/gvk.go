package gvk

import "k8s.io/apimachinery/pkg/runtime/schema"

var NetworkPolicy schema.GroupVersionKind = schema.GroupVersionKind{
	Group:   "cilium.io",
	Version: "v2",
	Kind:    "CiliumNetworkPolicy",
}
