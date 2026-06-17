package gvr

import "k8s.io/apimachinery/pkg/runtime/schema"

var Endpoint schema.GroupVersionResource = schema.GroupVersionResource{
	Group:    "cilium.io",
	Version:  "v2",
	Resource: "ciliumendpoints",
}

var Identity schema.GroupVersionResource = schema.GroupVersionResource{
	Group:    "cilium.io",
	Version:  "v2",
	Resource: "ciliumidentities",
}

var NetworkPolicy schema.GroupVersionResource = schema.GroupVersionResource{
	Group:    "cilium.io",
	Version:  "v2",
	Resource: "ciliumnetworkpolicies",
}

var ClusterwideNetworkPolicy schema.GroupVersionResource = schema.GroupVersionResource{
	Group:    "cilium.io",
	Version:  "v2",
	Resource: "ciliumclusterwidenetworkpolicies",
}

var CIDRGroup schema.GroupVersionResource = schema.GroupVersionResource{
	Group:    "cilium.io",
	Version:  "v2alpha1",
	Resource: "ciliumcidrgroups",
}
