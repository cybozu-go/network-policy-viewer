package e2e

import (
	"fmt"
	"net/netip"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/cybozu-go/network-policy-viewer/pkg/cidr"
)

type setTemplate struct {
	Include []string
	Exclude []string
}

func makeArray(tmpl []string) cidr.Array {
	input := make([]netip.Prefix, len(tmpl))
	for i, c := range tmpl {
		input[i] = netip.MustParsePrefix(c)
	}
	return cidr.NewArray(input)
}

func makeSet(tmpl setTemplate) cidr.Set {
	return cidr.NewSet(makeArray(tmpl.Include), makeArray(tmpl.Exclude))
}

func makeSetTemplate(s cidr.Set) setTemplate {
	var ret setTemplate
	arr := s.Include()
	cidrs := arr.CIDRs()
	ret.Include = make([]string, len(cidrs))
	for i := 0; i < len(cidrs); i++ {
		ret.Include[i] = cidrs[i].String()
	}

	arr = s.Exclude()
	cidrs = arr.CIDRs()
	ret.Exclude = make([]string, len(cidrs))
	for i := 0; i < len(cidrs); i++ {
		ret.Exclude[i] = cidrs[i].String()
	}
	return ret
}

func compareSetTemplate(g Gomega, actual, expected setTemplate) {
	g.ExpectWithOffset(1, actual.Include).To(HaveLen(len(expected.Include)))
	g.ExpectWithOffset(1, actual.Exclude).To(HaveLen(len(expected.Exclude)))
	for i := 0; i < len(actual.Include); i++ {
		g.ExpectWithOffset(1, actual.Include[i]).To(Equal(expected.Include[i]))
	}
	for i := 0; i < len(actual.Exclude); i++ {
		g.ExpectWithOffset(1, actual.Exclude[i]).To(Equal(expected.Exclude[i]))
	}
}

func testCIDR() {
	testNormalizeArray()
	testIntersectArray()
	testNormalizeSet()
	testOverlapSet()
}

func testNormalizeArray() {
	cases := []struct {
		Input    []string
		Expected []string
	}{
		{
			Input:    []string{"10.0.0.0/8"},
			Expected: []string{"10.0.0.0/8"},
		},
		{
			Input:    []string{"10.10.0.0/8"},
			Expected: []string{"10.0.0.0/8"},
		},
		{
			Input: []string{
				"10.0.0.0/8",
				"10.0.0.0/8",
			},
			Expected: []string{"10.0.0.0/8"},
		},
		{
			Input: []string{
				"10.0.0.0/8",
				"11.0.0.0/8",
			},
			Expected: []string{"10.0.0.0/7"},
		},
		{
			Input: []string{
				"10.0.0.0/8",
				"11.0.0.0/8",
				"12.0.0.0/8",
				"13.0.0.0/8",
			},
			Expected: []string{
				"10.0.0.0/7",
				"12.0.0.0/7",
			},
		},
		{
			Input: []string{
				"10.0.0.0/16",
				"10.1.0.0/16",
				"10.2.0.0/16",
				"10.3.0.0/16",
				"10.4.0.0/16",
				"10.5.0.0/16",
			},
			Expected: []string{
				"10.0.0.0/14",
				"10.4.0.0/15",
			},
		},
		{
			Input: []string{
				"10.0.0.0/16",
				"10.1.0.0/16",
				"10.2.0.0/16",
				"10.3.0.0/16",
				"10.6.0.0/16",
				"10.7.0.0/16",
			},
			Expected: []string{
				"10.0.0.0/14",
				"10.6.0.0/15",
			},
		},
	}
	It("should normalize array", func() {
		for _, c := range cases {
			By(fmt.Sprintf("normalizing %v", c.Input))
			arr := makeArray(c.Input)
			output := arr.CIDRs()

			Expect(output).To(HaveLen(len(c.Expected)))
			for i := 0; i < len(output); i++ {
				Expect(output[i].String()).To(Equal(c.Expected[i]))
			}
		}
	})
}

func testIntersectArray() {
	cases := []struct {
		Left     []string
		Right    []string
		Expected []string
	}{
		{
			Left:     []string{"10.0.0.0/8"},
			Right:    []string{"10.0.0.0/8"},
			Expected: []string{"10.0.0.0/8"},
		},
		{
			Left:     []string{"10.0.0.0/8"},
			Right:    []string{"10.0.0.0/12"},
			Expected: []string{"10.0.0.0/12"},
		},
		{
			Left:     []string{"10.0.0.0/8"},
			Right:    []string{"10.100.0.0/16"},
			Expected: []string{"10.100.0.0/16"},
		},
		{
			Left: []string{
				"10.0.0.0/8",
				"20.0.0.0/12",
			},
			Right: []string{
				"10.0.0.0/12",
				"20.0.0.0/8",
			},
			Expected: []string{
				"10.0.0.0/12",
				"20.0.0.0/12",
			},
		},
	}

	It("should intersect array", func() {
		for _, c := range cases {
			By(fmt.Sprintf("intersecting %v and %v", c.Left, c.Right))
			left := makeArray(c.Left)
			right := makeArray(c.Right)

			arr := left.Intersect(right)
			output := arr.CIDRs()

			Expect(output).To(HaveLen(len(c.Expected)))
			for i := 0; i < len(output); i++ {
				Expect(output[i].String()).To(Equal(c.Expected[i]))
			}
		}
	})
}

func testNormalizeSet() {
	cases := []struct {
		Input    setTemplate
		Expected setTemplate
	}{
		{
			Input: setTemplate{
				Include: []string{"10.0.0.0/8"},
			},
			Expected: setTemplate{
				Include: []string{"10.0.0.0/8"},
			},
		},
		{
			Input: setTemplate{
				Exclude: []string{"10.0.0.0/8"},
			},
		},
		{
			Input: setTemplate{
				Include: []string{"10.0.0.0/8"},
				Exclude: []string{"10.0.0.0/16"},
			},
			Expected: setTemplate{
				Include: []string{"10.0.0.0/8"},
				Exclude: []string{"10.0.0.0/16"},
			},
		},
		{
			Input: setTemplate{
				Include: []string{"10.0.0.0/8"},
				Exclude: []string{"10.0.0.0/8"},
			},
		},
		{
			Input: setTemplate{
				Include: []string{
					"10.0.0.0/8",
					"172.16.0.0/12",
				},
				Exclude: []string{"172.16.0.0/12"},
			},
			Expected: setTemplate{
				Include: []string{"10.0.0.0/8"},
			},
		},
	}

	It("should normalize set", func() {
		for _, c := range cases {
			By(fmt.Sprintf("normalizing %v", c.Input))
			s := makeSet(c.Input)
			actual := makeSetTemplate(s)
			compareSetTemplate(Default, actual, c.Expected)
		}
	})
}

func testOverlapSet() {
	cases := []struct {
		Left     setTemplate
		Right    setTemplate
		Expected bool
	}{
		{
			Left: setTemplate{
				Include: []string{"10.0.0.0/8"},
			},
			Right: setTemplate{
				Include: []string{"10.0.0.0/8"},
			},
			Expected: true,
		},
		{
			Left: setTemplate{
				Include: []string{"10.0.0.0/8"},
			},
			Right: setTemplate{
				Include: []string{"10.100.0.0/16"},
			},
			Expected: true,
		},
		{
			Left: setTemplate{
				Include: []string{"10.0.0.0/8"},
			},
			Right: setTemplate{
				Include: []string{"11.0.0.0/8"},
			},
			Expected: false,
		},
		{
			Left: setTemplate{
				Include: []string{"10.0.0.0/8"},
				Exclude: []string{"10.0.0.0/9"},
			},
			Right: setTemplate{
				Include: []string{"10.0.0.0/8"},
				Exclude: []string{"10.128.0.0/9"},
			},
			Expected: false,
		},
		{
			Left: setTemplate{
				Include: []string{"10.0.0.0/8"},
				Exclude: []string{"10.100.0.0/16"},
			},
			Right: setTemplate{
				Include: []string{"10.100.0.0/16"},
			},
			Expected: false,
		},
		{
			Left: setTemplate{
				Include: []string{"10.0.0.0/8"},
				Exclude: []string{"10.100.0.0/24"},
			},
			Right: setTemplate{
				Include: []string{"10.100.0.0/16"},
			},
			Expected: true,
		},
	}

	It("should calculate overlap between sets", func() {
		for _, c := range cases {
			By(fmt.Sprintf("testing %v and %v", c.Left, c.Right))
			left := makeSet(c.Left)
			right := makeSet(c.Right)
			actual := left.Overlaps(right)
			Expect(actual).To(Equal(c.Expected))
		}
	})
}
