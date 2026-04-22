package cidr

import (
	"net/netip"
	"slices"
)

type Array struct {
	arr []netip.Prefix
}

func NewArray(arr []netip.Prefix) Array {
	a := Array{arr}
	a.normalize()
	return a
}

func (a *Array) normalize() {
	for i := range a.arr {
		a.arr[i] = a.arr[i].Masked()
	}
	slices.SortFunc(a.arr, func(x, y netip.Prefix) int {
		return x.Compare(y)
	})

	ret := make([]netip.Prefix, 0)
	for _, p := range a.arr {
		if len(ret) > 0 && ContainsPrefix(ret[len(ret)-1], p) {
			continue
		}

		ret = append(ret, p)
		for len(ret) >= 2 {
			ix, iy := len(ret)-2, len(ret)-1
			x := ret[ix]
			y := ret[iy]
			if !IsSibling(x, y) {
				break
			}
			ret[ix] = netip.PrefixFrom(x.Addr(), x.Bits()-1)
			ret = ret[:iy]
		}
	}
	a.arr = ret
}

func (a *Array) CIDRs() []netip.Prefix {
	return a.arr
}

func (a *Array) Intersect(o Array) Array {
	ret := make([]netip.Prefix, 0)

	i, j := 0, 0
	for i < len(a.arr) && j < len(o.arr) {
		x, y := a.arr[i], o.arr[j]
		if !x.Overlaps(y) {
			if x.Addr().Less(y.Addr()) {
				i++
			} else {
				j++
			}
			continue
		}
		if ContainsPrefix(x, y) {
			ret = append(ret, y)
			j++
		} else {
			ret = append(ret, x)
			i++
		}
	}
	return Array{arr: ret}
}
