package cidr

import (
	"errors"
	"net"
	"strings"
)

var privateCIDRs []*net.IPNet

func init() {
	privateCIDRs, _, _ = ParseCIDRExpression("10.0.0.0/8,172.16.0.0/12,192.168.0.0/16")
}

func IsChildCIDR(parent, child *net.IPNet) bool {
	if parent == nil || child == nil {
		return false
	}
	if !parent.Contains(child.IP) {
		return false
	}
	p, _ := parent.Mask.Size()
	c, _ := child.Mask.Size()
	return p <= c
}

// ParseCIDRExpression parses a comma-separated CIDR expression into inclusive
// and exclusive CIDR rules. Rules prefixed with "!" are treated as exclusions.
func ParseCIDRExpression(expr string) (incl []*net.IPNet, excl []*net.IPNet, err error) {
	incl = make([]*net.IPNet, 0)
	excl = make([]*net.IPNet, 0)
	if expr == "" {
		return
	}

	fields := strings.Split(expr, ",")
	for _, f := range fields {
		not := false
		if f[0] == '!' {
			not = true
			f = f[1:]
		}

		var cidr *net.IPNet
		if _, cidr, err = net.ParseCIDR(f); err != nil {
			return
		}
		if not {
			excl = append(excl, cidr)
		} else {
			incl = append(incl, cidr)
		}
	}

	if len(incl) == 0 {
		err = errors.New("at least one inclusive CIDR rule should be specified")
	}
	return
}

// IsPrivateCIDR reports whether the given CIDR block is contained within an RFC 1918 private CIDR range.
func IsPrivateCIDR(c *net.IPNet) bool {
	for _, p := range privateCIDRs {
		if IsChildCIDR(p, c) {
			return true
		}
	}
	return false
}

// IsPublicCIDR reports whether the given CIDR block does not overlap any RFC 1918 private CIDR range.
func IsPublicCIDR(c *net.IPNet) bool {
	for _, p := range privateCIDRs {
		if IsChildCIDR(c, p) || IsChildCIDR(p, c) {
			return false
		}
	}
	return true
}
