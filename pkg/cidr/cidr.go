package cidr

import (
	"errors"
	"net/netip"
	"strings"
)

var (
	PrivateCIDRArray Array
	PrivateCIDRSet   Set
	PublicCIDRSet    Set
)

func init() {
	all := NewArray([]netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/0"),
	})
	PrivateCIDRArray = NewArray([]netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
	})
	PrivateCIDRSet = NewSet(PrivateCIDRArray, Array{})
	PublicCIDRSet = NewSet(all, PrivateCIDRArray)
}

func IsSibling(x, y netip.Prefix) bool {
	if x.Bits() == 0 {
		return false
	}
	if x.Bits() != y.Bits() {
		return false
	}
	x = x.Masked()
	y = y.Masked()
	x = netip.PrefixFrom(x.Addr(), x.Bits()-1).Masked()
	y = netip.PrefixFrom(y.Addr(), y.Bits()-1).Masked()
	return x == y
}

func ContainsPrefix(parent, child netip.Prefix) bool {
	parent = parent.Masked()
	child = child.Masked()
	return parent.Contains(child.Addr()) && parent.Bits() <= child.Bits()
}

// IsChildCIDR reports whether child is contained within parent.
func IsChildCIDR(parent, child netip.Prefix) bool {
	if !parent.Contains(child.Addr()) {
		return false
	}
	return parent.Bits() <= child.Bits()
}

// ParseCIDRExpression parses a comma-separated CIDR expression into inclusive
// and exclusive CIDR rules. Rules prefixed with "!" are treated as exclusions.
func ParseCIDRExpression(expr string) (*Set, error) {
	incl := make([]netip.Prefix, 0)
	excl := make([]netip.Prefix, 0)
	if expr == "" {
		return nil, nil
	}

	fields := strings.Split(expr, ",")
	for _, f := range fields {
		not := false
		if f[0] == '!' {
			not = true
			f = f[1:]
		}

		var cidr netip.Prefix
		var err error
		if cidr, err = netip.ParsePrefix(f); err != nil {
			return nil, err
		}
		if not {
			excl = append(excl, cidr)
		} else {
			incl = append(incl, cidr)
		}
	}

	if len(incl) == 0 {
		return nil, errors.New("at least one inclusive CIDR rule should be specified")
	}

	ret := NewSet(NewArray(incl), NewArray(excl))
	return &ret, nil
}
