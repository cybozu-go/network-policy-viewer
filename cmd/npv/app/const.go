package app

import "k8s.io/apimachinery/pkg/runtime/schema"

const (
	directionEgress  = "Egress"
	directionIngress = "Ingress"

	policyAllow = "Allow"
	policyDeny  = "Deny"

	trafficRoleSender   = "Sender"
	trafficRoleReceiver = "Receiver"
)

var gvrEndpoint schema.GroupVersionResource = schema.GroupVersionResource{
	Group:    "cilium.io",
	Version:  "v2",
	Resource: "ciliumendpoints",
}

var gvrIdentity schema.GroupVersionResource = schema.GroupVersionResource{
	Group:    "cilium.io",
	Version:  "v2",
	Resource: "ciliumidentities",
}

var gvrNetworkPolicy schema.GroupVersionResource = schema.GroupVersionResource{
	Group:    "cilium.io",
	Version:  "v2",
	Resource: "ciliumnetworkpolicies",
}

var gvrClusterwideNetworkPolicy schema.GroupVersionResource = schema.GroupVersionResource{
	Group:    "cilium.io",
	Version:  "v2",
	Resource: "ciliumclusterwidenetworkpolicies",
}

var gvkNetworkPolicy schema.GroupVersionKind = schema.GroupVersionKind{
	Group:   "cilium.io",
	Version: "v2",
	Kind:    "CiliumNetworkPolicy",
}
