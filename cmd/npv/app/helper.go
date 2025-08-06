package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"
)

var privateCIDRs []*net.IPNet

func init() {
	privateCIDRs, _, _ = parseCIDRFlag("10.0.0.0/8,172.16.0.0/12,192.168.0.0/16")
}

func parseCIDRFlag(expr string) (incl []*net.IPNet, excl []*net.IPNet, err error) {
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

func isChildCIDR(parent, child *net.IPNet) bool {
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

func isPrivateCIDR(c *net.IPNet) bool {
	for _, p := range privateCIDRs {
		if isChildCIDR(p, c) {
			return true
		}
	}
	return false
}

func isPublicCIDR(c *net.IPNet) bool {
	for _, p := range privateCIDRs {
		if isChildCIDR(c, p) {
			return false
		}
	}
	return true
}

func formatWithUnits(v int) string {
	if v < 1024 || !rootOptions.units {
		return strconv.Itoa(v)
	}

	units := "_KMGTPEZY"
	i := 0
	fv := float64(v)
	for fv >= 1024 {
		i += 1
		fv /= 1024
	}
	return fmt.Sprintf("%.1f%c", fv, units[i])
}

func computeAverage(bytes, count int) float64 {
	if count == 0 {
		return 0
	}
	return float64(bytes) / float64(count)
}

func writeSimpleOrJson(w io.Writer, content any, header []string, count int, values func(index int) []any) error {
	expr := make([][]any, 0)
	for i := range count {
		expr = append(expr, values(i))
	}

	if rootOptions.output == OutputSimple {
		header = slices.Clone(header)
		for j := 0; j < len(header); j++ {
			h := header[j]
			if strings.HasSuffix(h, ":") {
				h = h[:len(h)-1]
				header[j] = h
				width := len(h)
				for i := 0; i < count; i++ {
					v := fmt.Sprintf("%v", expr[i][j])
					width = max(width, len(v))
					expr[i][j] = v
				}

				format := fmt.Sprintf("%%%ds", width)
				header[j] = fmt.Sprintf(format, header[j])
				for i := 0; i < count; i++ {
					expr[i][j] = fmt.Sprintf(format, expr[i][j])
				}
			}
		}
	}

	switch rootOptions.output {
	case OutputJson:
		text, err := json.MarshalIndent(content, "", "  ")
		if err != nil {
			return err
		}
		_, err = w.Write(text)
		if err != nil {
			return err
		}
		_, err = w.Write([]byte{'\n'})
		return err
	case OutputSimple:
		tw := tabwriter.NewWriter(w, 0, 1, 1, ' ', 0)
		if !rootOptions.noHeaders {
			if _, err := tw.Write([]byte(strings.Join(header, "\t") + "\n")); err != nil {
				return err
			}
		}
		for i := range count {
			format := strings.Repeat("%v\t", len(header)-1) + "%v\n"
			if _, err := tw.Write([]byte(fmt.Sprintf(format, expr[i]...))); err != nil {
				return err
			}
		}
		return tw.Flush()
	default:
		return fmt.Errorf("unknown format: %s", rootOptions.output)
	}
}
