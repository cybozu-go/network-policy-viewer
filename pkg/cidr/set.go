package cidr

import (
	"net/netip"
	"slices"
	"strings"
)

type Set struct {
	include Array
	exclude Array
}

func NewSet(include, exclude Array) Set {
	s := Set{
		include: include,
		exclude: exclude,
	}
	s.normalize()
	return s
}

func (s *Set) normalize() {
	s.include.arr = slices.DeleteFunc(s.include.arr, func(i netip.Prefix) bool {
		for _, e := range s.exclude.arr {
			if e.Contains(i.Addr()) && e.Bits() <= i.Bits() {
				return true
			}
		}
		return false
	})
	s.exclude.arr = slices.DeleteFunc(s.exclude.arr, func(e netip.Prefix) bool {
		for _, i := range s.include.arr {
			if i.Overlaps(e) {
				return false
			}
		}
		return true
	})
}

func (s *Set) Include() Array {
	return s.include
}

func (s *Set) Exclude() Array {
	return s.exclude
}

func (s *Set) Overlaps(o Set) bool {
	ret := NewSet(s.include.Intersect(o.include), NewArray(append(s.exclude.arr, o.exclude.arr...)))
	return len(ret.include.arr) > 0
}

func (s *Set) String() string {
	incl := make([]string, len(s.include.arr))
	excl := make([]string, len(s.exclude.arr))
	for i, c := range s.include.arr {
		incl[i] = c.String()
	}
	for i, c := range s.exclude.arr {
		excl[i] = c.String()
	}
	ret := strings.Join(incl, "+")
	if len(s.exclude.arr) > 0 {
		ret += "-" + strings.Join(excl, "-")
	}
	return ret
}
