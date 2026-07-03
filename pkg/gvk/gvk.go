package gvk

import (
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var (
	ClusterwideNetworkPolicy schema.GroupVersionKind = ciliumv2.SchemeGroupVersion.WithKind("CiliumClusterwideNetworkPolicy")
	NetworkPolicy            schema.GroupVersionKind = ciliumv2.SchemeGroupVersion.WithKind("CiliumNetworkPolicy")
)
